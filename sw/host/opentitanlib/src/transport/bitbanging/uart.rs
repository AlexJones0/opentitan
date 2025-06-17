// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{bail, Result};
use serialport::Parity;
use thiserror::Error;

use crate::io::gpio::GpioBitbanging;
use crate::io::gpio::{BitbangEntry, GpioPin, PinMode, PullMode};
use crate::io::uart::{FlowControl, Uart};
use crate::test_utils::bitbanging::uart::{UartBitbangConfig, UartBitbangEncoder, UartStopBits};
use crate::transport::Transport;

#[derive(Error, Debug, PartialEq)]
pub enum UartBitbangError {
    #[error("Cannot write to UART TX while break is enabled")]
    TransmitDuringBreak,
}

/// Information related to bitbanging/sampling UART TX/RX pins respectively.
struct UartPins {
    #[allow(dead_code)]
    rx: Rc<dyn GpioPin>,
    tx: Rc<dyn GpioPin>,
    gpio_bitbanging: Rc<dyn GpioBitbanging>,
}

impl UartPins {
    fn new(rx: Rc<dyn GpioPin>, tx: Rc<dyn GpioPin>, transport: Rc<dyn Transport>) -> Result<Self> {
        Ok(Self {
            rx,
            tx,
            gpio_bitbanging: transport.gpio_bitbanging()?,
        })
    }

    /// Configure pinmux to allow TX bitbanging
    fn setup(&mut self) -> Result<()> {
        self.tx.set(
            Some(PinMode::PushPull),
            Some(true), // UART is idle high
            Some(PullMode::PullUp),
            None,
        )?;
        Ok(())
    }

    /// Set the TX pin to a specific output value.
    fn set_tx(&self, _enable: bool) -> Result<()> {
        self.tx.write(_enable)
    }

    /// Bitbang a waveform on the UART TX pin, using bit 0 of each sample.
    /// This function will block if `gpio_bitbanging.run()` blocks.
    fn bitbang_tx(&self, samples: &[u8], baud_rate: u32) -> Result<()> {
        let period = Duration::from_micros(1_000_000u64 / baud_rate as u64);
        let waveform = Box::new([BitbangEntry::Write(samples)]);
        let gpio_pins = [self.tx.borrow()];
        self.gpio_bitbanging.run(&gpio_pins, period, waveform)?;
        Ok(())
    }
}

/// Configurable UART options
#[derive(Debug)]
struct UartConfiguration {
    baud_rate: u32,
    parity: Parity,
    flow_control: FlowControl,
    break_condition: bool,
}

/// Stateful implementation of the bitbang UART, separated for clearer
/// interior mutability.
struct UartBitbangInterface {
    config: UartConfiguration,
    pins: UartPins,
    encoder: UartBitbangEncoder<0>,
}

impl UartBitbangInterface {
    /// Set the parity of the UART bitbanging interface, propagating the parity
    /// change to the bitbanging encoder.
    fn set_parity(&mut self, parity: Parity) {
        self.config.parity = parity;
        self.encoder.set_parity(parity);
    }

    fn write(&mut self, buf: &[u8]) -> Result<()> {
        if self.config.break_condition {
            bail!(UartBitbangError::TransmitDuringBreak);
        }
        let mut transaction = vec![];
        self.encoder.encode_characters(buf, &mut transaction);
        self.pins.bitbang_tx(&transaction, self.config.baud_rate)?;
        Ok(())
    }

    fn set_break(&mut self, _enable: bool) -> Result<()> {
        // The bitbanging interface supports set-length breaks, but the UART
        // trait doesn't yet have this so we just directly write to the pin.
        self.config.break_condition = _enable;
        self.pins.set_tx(!_enable)
    }
}

/// A UART implementation that wraps some underlying UART and replaces it with
/// corresponding bitbanging / GPIO monitoring logic using software.
pub struct BitbangWrapperUart {
    underlying: Rc<dyn Uart>,
    wrapper: RefCell<UartBitbangInterface>,
}

impl BitbangWrapperUart {
    pub fn new(
        uart: Rc<dyn Uart>,
        rx: Rc<dyn GpioPin>,
        tx: Rc<dyn GpioPin>,
        transport: Rc<dyn Transport>,
    ) -> Result<Self> {
        // Get initial parameters by querying the underlying UART
        let config = UartConfiguration {
            baud_rate: uart.get_baudrate().unwrap_or(57600),
            parity: uart.get_parity().unwrap_or(Parity::None),
            flow_control: uart.get_flow_control().unwrap_or(FlowControl::None),
            break_condition: false,
        };
        // TODO: no way to query stop bits yet, so assume 1 is used
        let encoding_config = UartBitbangConfig::new(8, UartStopBits::Stop1, 2, config.parity)?;
        let mut pins = UartPins::new(rx, tx, transport)?;
        pins.setup()?;
        let wrapper = UartBitbangInterface {
            config,
            pins,
            encoder: UartBitbangEncoder::new(encoding_config),
        };
        Ok(Self {
            underlying: uart,
            wrapper: RefCell::new(wrapper),
        })
    }
}

impl Uart for BitbangWrapperUart {
    fn get_baudrate(&self) -> Result<u32> {
        Ok(self.wrapper.borrow_mut().config.baud_rate)
    }

    fn set_baudrate(&self, baudrate: u32) -> Result<()> {
        match self.underlying.set_baudrate(baudrate) {
            Ok(r) => {
                self.wrapper.borrow_mut().config.baud_rate = baudrate;
                Ok(r)
            }
            Err(err) => Err(err),
        }
    }

    fn get_parity(&self) -> Result<Parity> {
        Ok(self.wrapper.borrow_mut().config.parity)
    }

    fn set_parity(&self, parity: Parity) -> Result<()> {
        match self.underlying.set_parity(parity) {
            Ok(r) => {
                self.wrapper.borrow_mut().set_parity(parity);
                Ok(r)
            }
            Err(err) => Err(err),
        }
    }

    fn get_flow_control(&self) -> Result<FlowControl> {
        Ok(self.wrapper.borrow_mut().config.flow_control)
    }

    fn set_flow_control(&self, flow_control: bool) -> Result<()> {
        match self.underlying.set_flow_control(flow_control) {
            Ok(r) => {
                self.wrapper.borrow_mut().config.flow_control =
                    self.underlying.get_flow_control()?;
                Ok(r)
            }
            Err(err) => Err(err),
        }
    }

    fn get_device_path(&self) -> Result<String> {
        self.underlying.get_device_path()
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // Not yet implemented
        self.underlying.read(buf)
    }

    fn read_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        // Not yet implemented
        self.underlying.read_timeout(buf, timeout)
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        self.wrapper.borrow_mut().write(buf)
    }

    fn clear_rx_buffer(&self) -> Result<()> {
        // Not yet implemented
        self.underlying.clear_rx_buffer()
    }

    fn set_break(&self, _enable: bool) -> Result<()> {
        self.wrapper.borrow_mut().set_break(_enable)
    }
}

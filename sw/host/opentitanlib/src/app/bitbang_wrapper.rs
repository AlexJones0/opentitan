// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use std::vec::Vec;

use anyhow::Result;
use serialport::Parity;

use crate::io::gpio::{GpioPin};
use crate::io::nonblocking_help::NonblockingHelp;
use crate::io::uart::{FlowControl, Uart};

pub struct UartPins {
    rx: Rc<dyn GpioPin>,
    tx: Rc<dyn GpioPin>,
}

pub struct BitbangWrapperUart {
    underlying: Rc<dyn Uart>,
    baud_rate: RefCell<u32>,
    parity: RefCell<Parity>,
    flow_control: RefCell<FlowControl>,
    rx_buffer: RefCell<Vec<u8>>,
    tx_buffer: RefCell<Vec<u8>>,
    pins: UartPins,
}

impl BitbangWrapperUart {

    pub fn new(uart: Rc<dyn Uart>, rx: Rc<dyn GpioPin>, tx: Rc<dyn GpioPin>) -> Result<Self> {
        let baud_rate = RefCell::new(uart.get_baudrate()?);
        let parity = RefCell::new(uart.get_parity()?);
        let flow_control = RefCell::new(uart.get_flow_control()?);
        Ok( Self {
            underlying: uart,
            baud_rate,
            parity,
            flow_control,
            rx_buffer: RefCell::new(Vec::<u8>::with_capacity(128)),
            tx_buffer: RefCell::new(Vec::<u8>::with_capacity(128)),
            pins: UartPins { rx, tx },
        })
    }
}

impl Uart for BitbangWrapperUart {

    fn get_baudrate(&self) -> Result<u32> {
        Ok(*self.baud_rate.borrow())
    }

    fn set_baudrate(&self, baudrate: u32) -> Result<()> {
        match self.underlying.set_baudrate(baudrate) {
            Ok(r) => {
                *self.baud_rate.borrow_mut() = baudrate;
                Ok(r)
            }
            Err(err) => Err(err)
        }
    }

    fn get_flow_control(&self) -> Result<FlowControl> {
        Ok(*self.flow_control.borrow())
    }

    fn set_flow_control(&self, flow_control: bool) -> Result<()> {
        match self.underlying.set_flow_control(flow_control) {
            Ok(r) => {
                *self.flow_control.borrow_mut() = self.underlying.get_flow_control()?;
                Ok(r)
            }
            Err(err) => Err(err)
        }
    }

    fn get_device_path(&self) -> Result<String> {
        self.underlying.get_device_path()
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.underlying.read(buf)
        // TODO: implement with bitbanging
    }

    fn read_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        self.underlying.read_timeout(buf, timeout)
        // TODO: implement with bitbanging
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        self.underlying.write(buf)
        // TODO: implement with bitbanging
    }

    fn clear_rx_buffer(&self) -> Result<()> {
        self.underlying.clear_rx_buffer()
    }

    fn set_break(&self, _enable: bool) -> Result<()> {
        unimplemented!();  // TODO: Probably not going to support?
    }

    fn get_parity(&self) -> Result<Parity> {
        Ok(*self.parity.borrow())
    }

    fn set_parity(&self, parity: Parity) -> Result<()> {
        match self.underlying.set_parity(parity) {
            Ok(r) => {
                *self.parity.borrow_mut() = parity;
                Ok(r)
            }
            Err(err) => Err(err)
        }
    }

    fn supports_nonblocking_read(&self) -> Result<bool> {
        // TODO: I'm not familiar with this so just say no for now.
        // Might just be a call to the underlying UART?
        Ok(false)
    }

    fn register_nonblocking_read(
        &self,
        _registry: &mio::Registry,
        _token: mio::Token,
    ) -> Result<()> {
        // TODO: I'm not familiar with this so not implemented for now.
        // Might just be a call to the underlying UART?
        unimplemented!();
    }

    fn nonblocking_help(&self) -> Result<Rc<dyn NonblockingHelp>> {
        // TODO: I'm not familiar with this so not implemented for now.
        // Might just be a call to the underlying UART?
        unimplemented!();
    }

}

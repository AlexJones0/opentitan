// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};
use std::vec::{Vec};

use anyhow::{bail, Result};
use serialport::Parity;

use crate::app::TransportWrapper;
use crate::bitbanging::uart::{UartBitbangConfig, UartBitbangDecoder, UartBitbangEncoder, UartTransfer};
use crate::io::gpio::{ClockNature, Edge, GpioBitbanging, GpioMonitoring, MonitoringEvent, MonitoringReadResponse};
use crate::io::gpio::{BitbangEntry, GpioPin, PinMode, PullMode};
use crate::io::uart::{FlowControl, Uart};
use crate::transport::Transport;

pub struct UartPins {
    rx: Rc<dyn GpioPin>,
    tx: Rc<dyn GpioPin>,
    decoder: UartBitbangDecoder<0>,
    gpio_bitbanging: Rc<dyn GpioBitbanging>,
    gpio_monitoring: Rc<dyn GpioMonitoring>,
    started_monitoring: bool,
    clock_resolution: u64,
    clock_offset: Option<u64>,
    initial_timestamp: Option<u64>,
    last_event: Option<MonitoringEvent>,
    last_sample_time: Option<u64>,
}

// TODO: combine this and the BitbangWrapperUart into one struct
// as the logical separation doesn't make sense and currently they share too much.
// All the methods here can just be added to `impl BitbangWrapperUart` instead of
// `impl Uart for BitbangWrapperUart`.
impl UartPins {

    pub fn new(rx: Rc<dyn GpioPin>, tx: Rc<dyn GpioPin>, transport_wrapper: &TransportWrapper, bitbang_config: UartBitbangConfig) -> Result<Self> {
        let gpio_monitoring = transport_wrapper.transport.gpio_monitoring()?;
        let clock_nature = gpio_monitoring.get_clock_nature()?;
        let ClockNature::Wallclock { resolution, offset } = clock_nature else {
            bail!("UART bitbanging RX monitoring needs a more reliable clock source");
        };
        Ok(Self {
            rx,
            tx,
            decoder: UartBitbangDecoder::new(bitbang_config)?,
            gpio_bitbanging: transport_wrapper.transport.gpio_bitbanging()?,
            gpio_monitoring: gpio_monitoring,
            started_monitoring: false,
            clock_resolution: resolution,
            clock_offset: offset,
            initial_timestamp: None,
            last_event: None,
            last_sample_time: None,
        })
    }

    fn start_monitoring_rx(&mut self) -> Result<()> {
        if self.started_monitoring {
            bail!("Cannot start monitoring UART RX as already monitoring");
        }
        self.started_monitoring = true;
        log::info!("Monitoring RX pin: {}", self.rx.get_internal_pin_name().unwrap());
        let start = self.gpio_monitoring.monitoring_start(&[self.rx.borrow()])?;
        self.initial_timestamp = Some(start.timestamp);
        // TODO: Do I need to handle start.initial_levels.first() == false?
        Ok(())
    }

    // Configure the pinmux settings and start GPIO monitoring to allow the
    // UART pins to function with bitbanging.
    pub fn setup(&mut self) -> Result<()> {
        self.rx.set_mode(PinMode::Input)?;
        self.tx.set(
            Some(PinMode::PushPull), 
            Some(true),  // UART is idle high
            Some(PullMode::PullUp),
            None,
        )?;
        self.start_monitoring_rx()?;
        Ok(())
    }


    fn reset_rx_events(&mut self) -> Result<()> {
        if !self.started_monitoring {
            return Ok(());
        }
        // For now, do not fully stop and start monitoring - instead just
        // read and thus clear all events.
        self.decoder.reset();
        self.gpio_monitoring.monitoring_read(&[self.rx.borrow()], true)?;
        self.last_event = None;
        self.last_sample_time = None;
        Ok(())
    }

    fn set_tx(&self, _enable: bool) -> Result<()> {
        self.tx.write(_enable)
    }

    fn bitbang_tx(&self, samples: &[u8], baud_rate: u32) -> Result<()> {
        let period = Duration::from_micros(1_000_000u64 / baud_rate as u64);
        let waveform = Box::new([BitbangEntry::Write(samples)]);
        log::info!("Bitbanging sample of {} bits at a baud rate of {} bps (period {} ns) on pin {}", samples.len(), baud_rate, period.as_nanos(), self.tx.get_internal_pin_name().unwrap());
        let gpio_pins = [self.tx.borrow()];
        self.gpio_bitbanging.run(
            &gpio_pins,
            period,
            waveform,
        )?;
        log::info!("Finished bitbanging!");
        Ok(())
    }

    fn timestamp_to_nanos(&self, timestamp: u64) -> u64 {
        // TODO: do I need to convert to u128 to be careful of overflows?
        (timestamp - self.initial_timestamp.unwrap()) * 1_000_000_000u64 / self.clock_resolution
    }

    fn decode_waveform(&mut self, events: Vec<MonitoringEvent>, timestamp: u64, period: &Duration) -> Result<Vec<u8>> {
        // The GpioMonitoring interface gives a VCD-like description of the
        // waveform as a set of events (edges) at timestamps. By knowing
        // the sampling period, resolution, and the previous event, we can
        // decode this into a fixed-interval waveform via sampling.
        log::info!("Wallclock resolution: {}, Sampling period as nanos: {}", self.clock_resolution, period.as_nanos());

        let mut decoded = Vec::new();
        let mut prev_sample_time: u64 = 0; 
        let mut value: u8 = 0x00;
        let mut events_iter = events.into_iter().peekable();

        let first_receive = self.last_sample_time.is_none();
        if first_receive {
            // Ensure the decoder is in a clean state
            if !self.decoder.is_idle() {
                self.decoder.reset();
            }

            // TODO: for now we assume that we either start when the UART is
            // idle, or in a break condition. In practice, we could have also
            // started monitoring mid-transaction, and so we'd want to detect
            // this case and wait for a known stable state, discarding junk.
            if let Some(first_event) = events_iter.peek() {
                if first_event.edge == Edge::Falling {
                    // Started monitoring when the line was already pulled high
                    prev_sample_time = self.timestamp_to_nanos(first_event.timestamp) - ((period.as_nanos() / 2) as u64);
                    value = 0x01;
                } else {
                    // Started monitoring before the line was pulled high, so
                    // begin from the first falling edge.
                    events_iter.next();
                    if let Some(second_event) = events_iter.peek() {
                        prev_sample_time = self.timestamp_to_nanos(second_event.timestamp) - ((period.as_nanos() / 2) as u64);
                        value = 0x01;
                    } else {
                        return Ok(decoded)
                    }
                }
            } else {
                return Ok(decoded);
            }
        } else {
            prev_sample_time = self.last_sample_time.unwrap();
            value = match self.last_event.unwrap().edge {
                Edge::Rising => 0x01,
                Edge::Falling => 0x00,
            }
        }

        for event in events_iter {
            if event.edge == Edge::Falling && value == 0 {
                bail!("Cannot have falling edge when current value is low");
            } else if event.edge == Edge::Rising && value == 1 {
                bail!("Cannot have rising edge when current value is high");
            }

            let next_timestamp = self.timestamp_to_nanos(event.timestamp);
            if next_timestamp < prev_sample_time {
                bail!("UART bitbanging events received out of order");
            }
            let time_elapsed = next_timestamp - prev_sample_time;
            let num_samples = time_elapsed / (period.as_nanos() as u64);
            prev_sample_time += (period.as_nanos() as u64) * num_samples;
            self.last_event = Some(event);

            for i in 0..num_samples {
                if self.decoder.is_idle() && event.edge == Edge::Falling {
                    // Optimisation: do not decode idle-high samples between transactions
                    break;
                }

                // TODO modularise better
                if let Some(transfer) = self.decoder.decode_sample(value)? {
                    match transfer {
                        UartTransfer::Byte { data } => { decoded.push(data); },
                        UartTransfer::Broken { error, .. } => { bail!(error); },
                        // TODO: do we need to do anything when we receive a break condition?
                        UartTransfer::Break => (),
                    }
                }
            }

            if self.decoder.is_idle() && event.edge == Edge::Falling {
                // Reset sampling time at the start of each transaction
                prev_sample_time = self.timestamp_to_nanos(event.timestamp) - ((period.as_nanos() / 2) as u64);
            }
            value = if value == 0x00 { 0x01 } else { 0x00 };
        }
        
        // If a transaction is finished, the final edge will be a rising edge
        // and the RX line is left idle (high), but our sampling mechanism only
        // decodes samples between edges. To avoid needing subsequent UART
        // transactions to complete previous ones, add sufficient idle bits until
        // the timestamp of the monitoring read until the decoder becomes idle again.
        self.last_sample_time = Some(prev_sample_time);
        if value != 0x00 {
            while !self.decoder.is_idle() {
                prev_sample_time += (period.as_nanos() as u64);
                if prev_sample_time >= timestamp {
                    break;
                }
                self.last_sample_time = Some(prev_sample_time);
                // TODO modularise better
                if let Some(transfer) = self.decoder.decode_sample(value)? {
                    match transfer {
                        UartTransfer::Byte { data } => { decoded.push(data); },
                        UartTransfer::Broken { error, .. } => { bail!(error); },
                        // TODO: do we need to do anything when we receive a break condition?
                        UartTransfer::Break => (),
                    }
                }
            }
        }

        Ok(decoded)
    }

    fn bitbang_rx(&mut self, baud_rate: u32) -> Result<Vec<u8>> {
        // We use the `gpio_monitoring` interface both for more accuracy,
        // and because it allows us to implement the async monitoring that
        // is required for UART transmission reception. This means we need
        // to decode edge-driven waveforms into logical samples, however.
        let sampling_period = Duration::from_nanos(1_000_000_000u64 / baud_rate as u64);
        let events = self.gpio_monitoring.monitoring_read(&[self.rx.borrow()], true)?;
        let mut read_timestamp = self.timestamp_to_nanos(events.timestamp);
        let decoded = self.decode_waveform(events.events, read_timestamp, &sampling_period)?;
        Ok(decoded)
    }
}

impl Drop for UartPins {
    fn drop(&mut self) {
        // Stop monitoring, ignoring any errors.
        let error = if self.started_monitoring {
            self.gpio_monitoring.monitoring_read(&[self.rx.borrow()], false).is_err()
        } else {
            false
        };
    }
}

pub struct BitbangWrapperUart {
    underlying: Rc<dyn Uart>,
    baud_rate: RefCell<u32>,
    parity: RefCell<Parity>,
    flow_control: RefCell<FlowControl>,
    pins: RefCell<UartPins>,
    encoder: UartBitbangEncoder<0>,
    rx_buffer: RefCell<VecDeque<u8>>,
}

impl BitbangWrapperUart {

    pub fn new(uart: Rc<dyn Uart>, rx: Rc<dyn GpioPin>, tx: Rc<dyn GpioPin>, transport_wrapper: &TransportWrapper) -> Result<Self> {
        // Construct the initial UART configuration by querying the underlying
        // UART implementation
        let baud_rate = RefCell::new(uart.get_baudrate().unwrap_or(57600));
        let parity = RefCell::new(uart.get_parity().unwrap_or(Parity::None));
        let flow_control = RefCell::new(uart.get_flow_control().unwrap_or(FlowControl::None));
        let bitbang_config = UartBitbangConfig::new(
            8, 1, 2, *parity.borrow()
        )?;

        let mut pins = UartPins::new(rx, tx, transport_wrapper, bitbang_config.clone())?;
        pins.setup()?;

        log::info!("UART created with baud_rate={}, parity={}", *baud_rate.borrow(), *parity.borrow());

        Ok(Self {
            underlying: uart,
            baud_rate,
            parity,
            flow_control,
            pins: RefCell::new(pins),
            encoder: UartBitbangEncoder::new(bitbang_config)?,
            rx_buffer: RefCell::new(VecDeque::new()),
        })
    }

    fn read_worker(&self, timeout: Option<Duration>) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Some(t) = timeout { 
                if (start.elapsed() > t) {
                    bail!("UART read timeout");
                }
            }
            let decoded = self.pins.borrow_mut().bitbang_rx(*self.baud_rate.borrow())?;
            if !decoded.is_empty() {
                let mut rx_buffer = self.rx_buffer.borrow_mut();
                rx_buffer.extend(decoded);
                break;
            }
        }
        Ok(())
    }

    fn read_buffer(&self, buf: &mut [u8]) -> Result<usize> {
        // Read as many bytes as we can & have available into the given buffer
        let mut rx_buffer = self.rx_buffer.borrow_mut();
        let mut bytes_read = 0;
        for byte in buf.iter_mut() {
            let Some(rx) = rx_buffer.pop_front() else {
                break;
            };
            *byte = rx;
            bytes_read += 1;
        }
        Ok(bytes_read)
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
        if flow_control {
            unimplemented!("Not yet implemented flow control");  // TODO
        }
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
        if self.rx_buffer.borrow().is_empty() {
            self.read_worker(None)?;
        }
        self.read_buffer(buf)
    }

    fn read_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        if self.rx_buffer.borrow().is_empty() {
            self.read_worker(Some(timeout))?;
        }
        self.read_buffer(buf)
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        // Note: as this is a software-controlled bitbanging implementation, bitbanging
        // is synchronous and will not complete until at least when all data to be written
        // has been transferred to Hyperdebug as a waveform to it to bitbang.
        let chars = buf.iter().map(|c| UartTransfer::Byte { data: *c }).collect::<Vec<_>>();
        let mut trans = vec![];
        self.encoder.encode_characters(&chars, &mut trans)?;
        log::info!("unencoded transaction: {:?}", chars);
        log::info!("encoded transaction: {:?}", trans);
        self.pins.borrow().bitbang_tx(&trans, *self.baud_rate.borrow());
        Ok(())
    }

    fn clear_rx_buffer(&self) -> Result<()> {
        self.pins.borrow_mut().reset_rx_events();
        self.rx_buffer.borrow_mut().clear();
        Ok(())
    }

    fn set_break(&self, _enable: bool) -> Result<()> {
        // The UART bitbanging interface supports using set-length breaks, but
        // since the UART trait interface doesn't yet support this functionality,
        // we instead just directly write to the pin.
        // (enable break = hold low)
        self.pins.borrow().set_tx(!_enable)
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
}

pub struct BitbangWrapperBuilder {
    // We cache the implementations of our bitbanging interfaces, as often the
    // same peripheral/IO is opened multiple times without dropping the previous
    // one, and we need to ensure the interfaces have consistent properties and
    // do not repeat e.g. muxing and pin monitoring logic.
    uarts: HashMap<String, Weak<dyn Uart>>,
}

impl BitbangWrapperBuilder {
    
    pub fn new() -> Self {
        Self {
            uarts: HashMap::new(),
        }
    }

    pub fn uart(&mut self, name: &str, transport_wrapper: &TransportWrapper) -> Result<Rc<dyn Uart>> {
        // If a BitbangWrapperUart already exists for this specific UART
        // instance and it is still in use, return a reference to it.
        if let Some(instance) = self.uarts.get(name) {
            if let Some(bitbang_uart) = instance.upgrade() {
                log::info!("Existing bitbanged UART found for {} - returning a reference", name);
                return Ok(bitbang_uart);
            } else {
                log::info!("Previous bitbanged UART found for {} but no longer exists - creating a new UART", name);
            }
        } else {
            log::info!("No existing bitbanged UART found for {} - creating a new UART", name)
        }

        // Otherwise, construct a new BitbangWrapperUart
        let uart = transport_wrapper.transport.uart(name)?;
        let rx = transport_wrapper.gpio_pin((name.to_string() + "_RX").as_str())?;
        let tx = transport_wrapper.gpio_pin((name.to_string() + "_TX").as_str())?;
        let bitbang_uart: Rc<dyn Uart> = Rc::new(BitbangWrapperUart::new(uart, rx, tx, transport_wrapper)?);
        self.uarts.insert(name.to_string(), Rc::downgrade(&bitbang_uart));
        
        Ok(bitbang_uart)
    }

}

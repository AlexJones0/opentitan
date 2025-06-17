// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::iter::Peekable;
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use anyhow::{bail, Result};
use serialport::Parity;
use thiserror::Error;

use crate::io::gpio::{BitbangEntry, GpioPin, PinMode, PullMode};
use crate::io::gpio::{
    ClockNature, Edge, GpioBitbanging, GpioMonitoring, MonitoringEvent, MonitoringReadResponse,
};
use crate::io::uart::{FlowControl, Uart};
use crate::test_utils::bitbanging::uart::{
    UartBitbangConfig, UartBitbangDecoder, UartBitbangEncoder, UartStopBits, UartTransfer,
};
use crate::transport::Transport;

#[derive(Error, Debug, PartialEq)]
pub enum UartBitbangError {
    #[error("Uart bitbanging RX monitoring needs a more reliable clock source")]
    InaccurateMonitoringClock,
    #[error("Cannot start monitoring UART RX as already monitoring")]
    AlreadyMonitoring,
    #[error("RX monitoring recorded double rising edge")]
    DoubleRisingEdge,
    #[error("RX monitoring recorded double falling edge")]
    DoubleFallingEdge,
    #[error("RX monitoring provided edges out-of-order")]
    EdgesOutOfOrder,
    #[error("Cannot write to UART TX while break is enabled")]
    TransmitDuringBreak,
}

/// Information related to bitbanging/sampling UART TX/RX pins respectively.
struct UartPins {
    rx: Rc<dyn GpioPin>,
    tx: Rc<dyn GpioPin>,
    gpio_bitbanging: Rc<dyn GpioBitbanging>,
    gpio_monitoring: Rc<dyn GpioMonitoring>,
    pub started_monitoring: bool,
    pub clock_resolution: u64,
    pub initial_timestamp: Option<u64>,
}

impl UartPins {
    fn new(rx: Rc<dyn GpioPin>, tx: Rc<dyn GpioPin>, transport: Rc<dyn Transport>) -> Result<Self> {
        let gpio_monitoring = transport.gpio_monitoring()?;
        let clock_nature = gpio_monitoring.get_clock_nature()?;
        let ClockNature::Wallclock { resolution, .. } = clock_nature else {
            bail!(UartBitbangError::InaccurateMonitoringClock);
        };
        Ok(Self {
            rx,
            tx,
            gpio_bitbanging: transport.gpio_bitbanging()?,
            gpio_monitoring,
            started_monitoring: false,
            clock_resolution: resolution,
            initial_timestamp: None,
        })
    }

    fn start_monitoring_rx(&mut self) -> Result<()> {
        if self.started_monitoring {
            bail!(UartBitbangError::AlreadyMonitoring);
        }
        self.started_monitoring = true;
        log::debug!(
            "Monitoring RX pin: {}",
            self.rx.get_internal_pin_name().unwrap()
        );
        let start = self.gpio_monitoring.monitoring_start(&[self.rx.borrow()])?;
        self.initial_timestamp = Some(start.timestamp);
        Ok(())
    }

    /// Configure pinmux & start GPIO monitoring to allow TX/RX bitbanging.
    fn setup(&mut self) -> Result<()> {
        self.rx.set_mode(PinMode::Input)?;
        self.tx.set(
            Some(PinMode::PushPull),
            Some(true), // UART is idle high
            Some(PullMode::PullUp),
            None,
        )?;
        self.start_monitoring_rx()?;
        Ok(())
    }

    /// Clear all RX edge read events from the GPIO monitor
    fn reset_rx_events(&mut self) -> Result<()> {
        if self.started_monitoring {
            self.gpio_monitoring
                .monitoring_read(&[self.rx.borrow()], true)?;
        }
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

    /// Read the UART RX waveform as an ordered list of events (edges) since the
    /// last read / since monitoring started.
    fn bitbang_rx(&self) -> Result<MonitoringReadResponse> {
        self.gpio_monitoring
            .monitoring_read(&[self.rx.borrow()], true)
    }
}

impl Drop for UartPins {
    fn drop(&mut self) {
        // Stop monitoring the RX pin.
        if self.started_monitoring
            && self
                .gpio_monitoring
                .monitoring_read(&[self.rx.borrow()], false)
                .is_err()
        {
            log::warn!("Error when trying to stop monitoring the RX pin");
        }
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
    decoder: UartBitbangDecoder<0>,
    rx_buffer: VecDeque<u8>,
    last_event: Option<MonitoringEvent>,
    next_sample_time: Option<u64>,
}

impl UartBitbangInterface {
    /// Set the parity of the UART bitbanging interface, propagating the parity
    /// change to the bitbanging encoder/decoder.
    fn set_parity(&mut self, parity: Parity) {
        self.config.parity = parity;
        self.encoder.set_parity(parity);
        self.decoder.set_parity(parity);
    }

    /// Convert a timestamp received from the gpio monitoring interface to a
    /// time relative to the started of RX monitoring, in nanoseconds.
    fn timestamp_to_nanos(&self, timestamp: u64) -> Result<u64> {
        let Some(initial_timestamp) = self.pins.initial_timestamp else {
            bail!("Cannot compute time before measuring an initial timestamp");
        };
        let timestamp_delta = (timestamp - initial_timestamp) as u128;
        let nanos = timestamp_delta * 1_000_000_000u128 / self.pins.clock_resolution as u128;
        Ok(nanos as u64)
    }

    /// Calculates the number of samples between two timestamps, assuming a sample
    /// was taken at the given `from` time.
    fn samples_since(&self, from: u64, until: u64, period_ns: u64) -> u64 {
        let time_elapsed = until - from;
        time_elapsed / period_ns
    }

    /// Consume edge events until several identical samples are found between
    /// edges. Allows us to wait for a break condition / idle even if monitoring
    /// starts mid-transmission. Returns `true` if in a stable state.
    fn sample_until_stable_state<I: Iterator<Item = MonitoringEvent>>(
        &mut self,
        events: &mut Peekable<I>,
        end_time: u64,
        period_ns: u64,
    ) -> Result<bool> {
        let frame_bit_time = self.encoder.config.bit_time_per_frame() as u64;
        let last_ts = if let Some(last_event) = self.last_event {
            last_event.timestamp
        } else if let Some(initial_timestamp) = self.pins.initial_timestamp {
            initial_timestamp
        } else {
            bail!("Cannot wait for a stable state before measuring an initial timestamp");
        };
        let mut last_time = self.timestamp_to_nanos(last_ts)?;

        while let Some(event) = events.peek() {
            let timestamp = self.timestamp_to_nanos(event.timestamp)?;
            if self.samples_since(last_time, timestamp, period_ns) > frame_bit_time {
                return Ok(true);
            }
            last_time = timestamp;
            self.last_event = events.next();
        }
        Ok(self.samples_since(last_time, end_time, period_ns) > frame_bit_time)
    }

    /// Determine the next sample time and current RX value from state info.
    /// If not previously sampled, consumes events until the RX transmission
    /// is stable and synchronises with the next falling edge.
    fn get_last_state<I: Iterator<Item = MonitoringEvent>>(
        &mut self,
        events: &mut Peekable<I>,
        end_time: u64,
        period_ns: u64,
    ) -> Result<Option<(u64, u8)>> {
        // If we have information stored from a previous sample, retrieve it.
        if let Some(next_sample_time) = self.next_sample_time {
            let Some(last_event) = self.last_event else {
                bail!("Previous sampling time exists but previous event does not");
            };
            let value = match last_event.edge {
                Edge::Rising => 0x01,
                Edge::Falling => 0x00,
            };
            return Ok(Some((next_sample_time, value)));
        };

        // No previous sampling, so wait for a stable RX level to avoid desync
        if !self.sample_until_stable_state(events, end_time, period_ns)? {
            return Ok(None);
        }

        // Identify & synchronise with the first falling edge
        let Some(first_event) = events.peek() else {
            return Ok(None);
        };
        let edge_time = if first_event.edge == Edge::Falling {
            self.timestamp_to_nanos(first_event.timestamp)?
        } else {
            events.next();
            let Some(second_event) = events.peek() else {
                return Ok(None);
            };
            self.timestamp_to_nanos(second_event.timestamp)?
        };
        let next_sample_time = edge_time + period_ns / 2;
        Ok(Some((next_sample_time, 0x01)))
    }

    /// Uses the bitbanging decoder to decode a given RX pin sample.
    fn decode_sample(&mut self, sample: u8, decoded: &mut Vec<u8>) -> Result<()> {
        if let Some(transfer) = self.decoder.decode_sample(sample)? {
            match transfer {
                UartTransfer::Byte { data } => decoded.push(data),
                UartTransfer::Broken { error, .. } => {
                    bail!(error)
                }
                UartTransfer::Break => (),
            }
        }
        Ok(())
    }

    /// Decodes a given RX waveform edge, calculating and decoding samples of
    /// the RX pin between this edge and the previously decoded edge.
    fn decode_edge(
        &mut self,
        event: MonitoringEvent,
        decoded: &mut Vec<u8>,
        period_ns: u64,
        next_sample_time: &mut u64,
        value: &mut u8,
    ) -> Result<()> {
        if event.edge == Edge::Falling && *value == 0 {
            bail!(UartBitbangError::DoubleFallingEdge);
        } else if event.edge == Edge::Rising && *value == 1 {
            bail!(UartBitbangError::DoubleRisingEdge);
        }
        let sampling_end = self.timestamp_to_nanos(event.timestamp)? + period_ns;
        if sampling_end < *next_sample_time {
            bail!(UartBitbangError::EdgesOutOfOrder)
        }

        // Calculate & decode samples between edges
        let num_samples = self.samples_since(*next_sample_time, sampling_end, period_ns);
        *next_sample_time += period_ns * num_samples;
        for _ in 0..num_samples {
            if self.decoder.is_idle() && event.edge == Edge::Falling {
                // Optimisation: don't decode idle-high samples between frames
                break;
            }
            self.decode_sample(*value, decoded)?;
        }

        if self.decoder.is_idle() && event.edge == Edge::Falling {
            // Reset sampling time at the start of each transaction
            *next_sample_time = self.timestamp_to_nanos(event.timestamp)? + period_ns / 2;
        }
        self.last_event = Some(event);
        *value = if *value == 0x00 { 0x01 } else { 0x00 };
        Ok(())
    }

    /// Decode a given RX waveform into UART frames, where the waveform is an
    /// ordered vector of edges monitored on RX, and the time at which the
    /// monitoring was performed (i.e. the end).
    fn decode_waveform(
        &mut self,
        events: Vec<MonitoringEvent>,
        end_time: u64,
        period: &Duration,
    ) -> Result<Vec<u8>> {
        let mut decoded = Vec::new();
        let mut events_iter = events.into_iter().peekable();
        let period_ns = period.as_nanos() as u64;
        let last_state = self.get_last_state(&mut events_iter, end_time, period_ns)?;
        let Some((mut next_sample_time, mut value)) = last_state else {
            // Not enough events recorded to find a starting state.
            return Ok(decoded);
        };
        for event in events_iter {
            self.decode_edge(
                event,
                &mut decoded,
                period_ns,
                &mut next_sample_time,
                &mut value,
            )?;
        }
        self.next_sample_time = Some(next_sample_time);
        // When a frame finishes, a final rising edge leaves the RX line high,
        // but our sampling mechanism only decodes samples between edges. To
        // avoid requiring subsequent transmissions, add idle bits until the
        // read timestamp (while the decoder is active).
        if value != 0x00 {
            while !self.decoder.is_idle() {
                next_sample_time += period_ns;
                if next_sample_time >= end_time {
                    break;
                }
                self.next_sample_time = Some(next_sample_time);
                self.decode_sample(value, &mut decoded)?;
            }
        }
        Ok(decoded)
    }

    /// Read an event-based RX waveform using the `gpio_monitoring` interface,
    /// then perform uniform sampling and decode the sampled UART output.
    fn read_decoded(&mut self, baud_rate: u32) -> Result<Vec<u8>> {
        let sampling_period = Duration::from_nanos(1_000_000_000u64 / baud_rate as u64);
        let events = self.pins.bitbang_rx()?;
        let read_timestamp = self.timestamp_to_nanos(events.timestamp)?;
        let decoded = self.decode_waveform(events.events, read_timestamp, &sampling_period)?;
        Ok(decoded)
    }

    /// Read & decode any incoming UART data and store it in the `rx_buffer`.
    fn read_worker(&mut self, timeout: Option<Duration>) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Some(t) = timeout {
                if start.elapsed() > t {
                    break;
                }
            }
            let decoded = self.read_decoded(self.config.baud_rate)?;
            if !decoded.is_empty() {
                for &ch in decoded.iter() {
                    if self.config.flow_control == FlowControl::None {
                        self.rx_buffer.push_back(ch);
                        continue;
                    }
                    // Handle XON/XOFF flow control characters
                    if ch == FlowControl::Resume as u8 {
                        log::debug!("Got RESUME");
                        self.config.flow_control = FlowControl::Resume;
                        continue;
                    } else if ch == FlowControl::Pause as u8 {
                        log::debug!("Got PAUSE");
                        self.config.flow_control = FlowControl::Pause;
                        continue;
                    }
                    self.rx_buffer.push_back(ch);
                }
                break; // Read until we get any data
            }
        }
        Ok(())
    }

    /// Read received data out of FIFO `rx_buffer` into a given buffer.
    fn read_buffer(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Read as many bytes as we can & have available
        let mut bytes_read = 0;
        for byte in buf.iter_mut() {
            let Some(rx) = self.rx_buffer.pop_front() else {
                break;
            };
            *byte = rx;
            bytes_read += 1;
        }
        Ok(bytes_read)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.rx_buffer.is_empty() {
            self.read_worker(None)?;
        }
        self.read_buffer(buf)
    }

    fn read_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        if self.rx_buffer.is_empty() {
            self.read_worker(Some(timeout))?;
        }
        self.read_buffer(buf)
    }

    fn write(&mut self, buf: &[u8]) -> Result<()> {
        if self.config.break_condition {
            bail!(UartBitbangError::TransmitDuringBreak);
        }
        if self.config.flow_control == FlowControl::None {
            let mut transaction = vec![];
            self.encoder.encode_characters(buf, &mut transaction);
            self.pins.bitbang_tx(&transaction, self.config.baud_rate)?;
            return Ok(());
        }

        // Warning: using flow control will likely slow down UART operation, since it
        // splits up transmissions into individual bitbang operations per UART frame,
        // which may be costly.
        let mut transaction = vec![];
        for &char in buf.iter() {
            // Read to check for any XOFF characters, and only send when flow
            // control is resumed.
            loop {
                self.read_worker(Some(Duration::ZERO))?;
                if self.config.flow_control == FlowControl::Resume {
                    break;
                }
            }
            transaction.clear();
            self.encoder.encode_character(char, &mut transaction);
            self.pins.bitbang_tx(&transaction, self.config.baud_rate)?;
            // No need to pace to account for device-internal buffer as bitbanging
            // operation should be synchronous (already completed).
        }
        Ok(())
    }

    fn clear_rx_buffer(&mut self) -> Result<()> {
        self.pins.reset_rx_events()?;
        self.rx_buffer.clear();
        self.decoder.reset();
        self.last_event = None;
        self.next_sample_time = None;
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
        // TODO: no way to query stop bits yet, so assume 2 are used.
        let encoding_config = UartBitbangConfig::new(8, UartStopBits::Stop2, 2, config.parity)?;
        let mut pins = UartPins::new(rx, tx, transport)?;
        pins.setup()?;
        let wrapper = UartBitbangInterface {
            config,
            pins,
            encoder: UartBitbangEncoder::new(encoding_config.clone()),
            decoder: UartBitbangDecoder::new(encoding_config),
            rx_buffer: VecDeque::new(),
            last_event: None,
            next_sample_time: None,
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
        self.wrapper.borrow_mut().read(buf)
    }

    fn read_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        self.wrapper.borrow_mut().read_timeout(buf, timeout)
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        self.wrapper.borrow_mut().write(buf)
    }

    fn clear_rx_buffer(&self) -> Result<()> {
        self.wrapper.borrow_mut().clear_rx_buffer()
    }

    fn set_break(&self, _enable: bool) -> Result<()> {
        self.wrapper.borrow_mut().set_break(_enable)
    }
}

// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use std::vec::Vec;

use anyhow::{bail, ensure, Result};
use thiserror::Error;

use crate::io::gpio::GpioBitbanging;
use crate::io::gpio::{BitbangEntry, GpioPin, PinMode, PullMode};
use crate::io::spi::{
    AssertChipSelect, ClockPhase, ClockPolarity, MaxSizes, SpiError, Target, TargetChipDeassert,
    Transfer, TransferMode,
};
use crate::test_utils::bitbanging::spi::{
    SpiBitbangConfig, SpiBitbangDecoder, SpiBitbangEncoder, SpiDataMode, SpiEncodingDelays,
    SpiEndpoint,
};
use crate::transport::{Transport, TransportError};

#[derive(Error, Debug, PartialEq)]
pub enum SpiBitbangError {
    #[error("Cannot bitbang SPI pins before configuring them for the required data mode")]
    PinsNotConfigured,
    #[error("Mismatched SPI decoding length: {0} != {1}")]
    MismatchedDecodingLength(usize, usize),
}

/// Information related to bitbanging/sampling SPI pins.
pub struct SpiPins {
    sck: Rc<dyn GpioPin>,
    copi: Rc<dyn GpioPin>,              // Host out, device in
    cipo: Rc<dyn GpioPin>,              // Host in, device out
    d2_3: Option<[Rc<dyn GpioPin>; 2]>, // Extra data lines for Quad SPI
    cs: Rc<dyn GpioPin>,
    gpio_bitbanging: Rc<dyn GpioBitbanging>,
    configured_data_mode: Option<SpiDataMode>,
}

impl SpiPins {
    pub fn new(
        sck: Rc<dyn GpioPin>,
        copi: Rc<dyn GpioPin>,
        cipo: Rc<dyn GpioPin>,
        cs: Rc<dyn GpioPin>,
        d2_3: Option<[Rc<dyn GpioPin>; 2]>,
        transport: Rc<dyn Transport>,
    ) -> Result<Self> {
        Ok(Self {
            sck,
            copi,
            cipo,
            cs,
            d2_3,
            gpio_bitbanging: transport.gpio_bitbanging()?,
            configured_data_mode: None,
        })
    }

    fn update_pins(
        &mut self,
        sck: Option<&Rc<dyn GpioPin>>,
        copi: Option<&Rc<dyn GpioPin>>,
        cipo: Option<&Rc<dyn GpioPin>>,
        cs: Option<&Rc<dyn GpioPin>>,
    ) {
        if sck.is_some() || copi.is_some() || cipo.is_some() || cs.is_some() {
            self.configured_data_mode = None;
        }
        if let Some(sck_pin) = sck {
            self.sck = Rc::clone(sck_pin);
        }
        if let Some(copi_pin) = copi {
            self.copi = Rc::clone(copi_pin);
        }
        if let Some(cipo_pin) = cipo {
            self.cipo = Rc::clone(cipo_pin);
        }
        if let Some(cs_pin) = cs {
            self.cs = Rc::clone(cs_pin);
        }
    }

    // Configure pinmux to allow SPI bitbanging.
    // Only supports single data transfer mode for now (no dual/quad SPI).
    fn setup(&mut self, data_mode: SpiDataMode, transfer_mode: TransferMode) -> Result<()> {
        let clk_idle_level = transfer_mode.polarity() == ClockPolarity::IdleHigh;
        match data_mode {
            SpiDataMode::Single => {
                self.sck.set(
                    Some(PinMode::PushPull),
                    Some(clk_idle_level), // Match CPOL configuration
                    Some(PullMode::PullUp),
                    None,
                )?;
                self.cs.set(
                    Some(PinMode::PushPull),
                    Some(true), // CS is active-low
                    Some(PullMode::PullUp),
                    None,
                )?;
                self.copi.set_mode(PinMode::PushPull)?;
                self.cipo.set_mode(PinMode::Input)?;
            }
            // TODO: add dual/quad data mode support
            SpiDataMode::Dual => bail!(TransportError::CommunicationError(
                "Bitbanged transport does not support Dual SPI".to_string()
            )),
            SpiDataMode::Quad => bail!(TransportError::CommunicationError(
                "Bitbanged transport does not support Quad SPI".to_string()
            )),
        }
        self.configured_data_mode = Some(data_mode);
        Ok(())
    }

    fn assert_cs(&mut self, assert: bool) -> Result<()> {
        self.cs.write(!assert) // CS is active-low
    }

    /// Bitbang a waveform on the SPI pins. This function will block if
    /// `gpio_bitbanging.run()` blocks. The bitbanging/sampling behaviour depends
    /// on the `BitbangEntry` type provided.
    fn bitbang(&self, samples: BitbangEntry, clock_rate: u32) -> Result<()> {
        ensure!(
            self.configured_data_mode.is_some(),
            SpiBitbangError::PinsNotConfigured
        );
        // 2 samples per clock (falling & rising edge)
        let period = Duration::from_nanos((1_000_000_000u64 / clock_rate as u64) / 2);
        let waveform = Box::new([samples]);
        // The order of these GPIO pins should match the index order used for
        // the bitbanging encoder/decoder.
        let mut gpio_pins = Vec::from([
            self.sck.borrow(),
            self.cs.borrow(),
            self.copi.borrow(),
            self.cipo.borrow(),
        ]);
        if let Some(data_mode) = self.configured_data_mode {
            // TODO: This currently causes execution of the `gpio bit-bang` command to
            // hang and timeout on the Hyperdebug backend due to an issue with the
            // Hyperdebug firmware command implementations.
            //
            // Likely due to USB<->USART buffer sizes and/or the lack of flow control
            // on the EC console interface, the bitbang command becomes too long and so
            // the host doesn't detect a valid echo response, since some ending bytes
            // are missed. This does not occur if the command is smaller than 64
            // characters (e.g. bitbanging only 5 pins).
            if data_mode == SpiDataMode::Quad {
                if let Some(data_pins) = &self.d2_3 {
                    gpio_pins.push(data_pins[0].borrow());
                    gpio_pins.push(data_pins[1].borrow());
                }
            }
        }
        self.gpio_bitbanging.run(&gpio_pins, period, waveform)?;
        Ok(())
    }
}

/// Configurable SPI options
#[derive(Debug)]
struct SpiConfiguration {
    transfer_mode: TransferMode,
    data_mode: SpiDataMode,
    bits_per_word: u32,
    max_speed: u32,
    max_transfer_count: usize,
    max_transfer_sizes: MaxSizes,
}

/// Stateful implementation of the bitbang SPI, separated for clearer
/// interior mutability.
struct SpiBitbangInterface {
    config: SpiConfiguration,
    pins: SpiPins,
    cs_asserted_count: u32,
    encoder: SpiBitbangEncoder<2, 3, 4, 5, 0, 1>,
    decoder: SpiBitbangDecoder<2, 3, 4, 5, 0, 1>,
}

impl SpiBitbangInterface {
    /// Request assertion/deassertion of the Chip Select
    fn do_assert_cs(&mut self, assert: bool) -> Result<()> {
        if assert {
            if self.cs_asserted_count == 0 {
                self.pins.assert_cs(true)?;
            }
            self.cs_asserted_count += 1;
        } else {
            if self.cs_asserted_count == 1 {
                self.pins.assert_cs(false)?;
            }
            self.cs_asserted_count -= 1;
        }
        Ok(())
    }

    fn set_pins(
        &mut self,
        sck: Option<&Rc<dyn GpioPin>>,
        copi: Option<&Rc<dyn GpioPin>>,
        cipo: Option<&Rc<dyn GpioPin>>,
        cs: Option<&Rc<dyn GpioPin>>,
    ) -> Result<()> {
        self.pins.update_pins(sck, copi, cipo, cs);
        self.pins
            .setup(self.config.data_mode, self.config.transfer_mode)?;
        Ok(())
    }

    fn get_clock_rate(&self) -> u32 {
        // TODO: for now, we always run at half the max configured speed. This
        // works fine for Hyperdebug, as clock rates that are too high are
        // clamped at the fastest speed Hyperdebug can achieve. If a backend is
        // added that requires valid rates, a better solution is required.
        self.config.max_speed.div_ceil(2)
    }

    fn run_transaction(
        &mut self,
        transaction: &mut [Transfer],
        supports_bidirectional: bool,
    ) -> Result<()> {
        let mut samples = Vec::new();
        let mut reads = Vec::new();

        self.encoder.assert_cs(true, &mut samples)?;
        for transfer in transaction {
            match transfer {
                Transfer::Write(wbuf) => {
                    ensure!(
                        wbuf.len() <= self.config.max_transfer_sizes.write,
                        SpiError::InvalidDataLength(wbuf.len())
                    );
                    self.encoder.encode_write(wbuf, &mut samples)?;
                }
                Transfer::Read(rbuf) => {
                    ensure!(
                        rbuf.len() <= self.config.max_transfer_sizes.read,
                        SpiError::InvalidDataLength(rbuf.len())
                    );
                    let read_start = samples.len();
                    let bytes_per_word = self.config.bits_per_word.div_ceil(8) as usize;
                    let words = rbuf.len().div_ceil(bytes_per_word);
                    self.encoder.encode_read(words, &mut samples)?;
                    let read_end = samples.len();
                    reads.push((rbuf, read_start, read_end));
                }
                Transfer::Both(wbuf, rbuf) => {
                    ensure!(
                        supports_bidirectional,
                        TransportError::CommunicationError(
                            "Bitbanged transport does not support bidirectional SPI".to_string()
                        )
                    );
                    ensure!(
                        wbuf.len() == rbuf.len(),
                        SpiError::MismatchedDataLength(wbuf.len(), rbuf.len())
                    );
                    ensure!(
                        rbuf.len() <= self.config.max_transfer_sizes.read
                            && wbuf.len() <= self.config.max_transfer_sizes.write,
                        SpiError::InvalidDataLength(wbuf.len())
                    );
                    let read_start = samples.len();
                    self.encoder.encode_write(wbuf, &mut samples)?;
                    let read_end = samples.len();
                    reads.push((rbuf, read_start, read_end));
                }
                Transfer::TpmPoll => bail!(TransportError::UnsupportedOperation),
                Transfer::GscReady => bail!(TransportError::UnsupportedOperation),
            }
        }
        self.encoder.assert_cs(false, &mut samples)?;

        let clock_rate = self.get_clock_rate();
        if reads.is_empty() {
            self.pins
                .bitbang(BitbangEntry::Write(&samples), clock_rate)?;
        } else if !samples.is_empty() {
            // Inputs are captured before outputs are applied, so to get the final
            // input we must include one extra dummy sample at the end.
            samples.push(*samples.last().unwrap());
            let mut read_samples = vec![0; samples.len()];
            let waveform = BitbangEntry::Both(&samples, &mut read_samples);
            self.pins.bitbang(waveform, clock_rate)?;
            for (rbuf, start, end) in reads {
                let decoded = self
                    .decoder
                    .run(read_samples[(start + 1)..(end + 1)].to_vec())?;
                ensure!(
                    decoded.len() == rbuf.len(),
                    SpiBitbangError::MismatchedDecodingLength(decoded.len(), rbuf.len())
                );
                rbuf.copy_from_slice(&decoded);
            }
        }

        Ok(())
    }
}

/// A SPI implementation that wraps some underlying SPI `Target` and replaces
/// it with corresonding bitbanging / GPIO monitoring logic using software.
pub struct BitbangWrapperSpi {
    underlying: Rc<dyn Target>,
    wrapper: RefCell<SpiBitbangInterface>,
}

impl BitbangWrapperSpi {
    pub fn new(spi: Rc<dyn Target>, mut pins: SpiPins) -> Result<Self> {
        let config = SpiConfiguration {
            transfer_mode: spi.get_transfer_mode().unwrap_or(TransferMode::Mode0),
            // There is no way of querying the data mode of the underyling SPI,
            // so for now assume we start in standard Single mode.
            data_mode: SpiDataMode::Single,
            bits_per_word: spi.get_bits_per_word().unwrap_or(8),
            max_speed: spi.get_max_speed().unwrap_or(50_000),
            max_transfer_count: spi.get_max_transfer_count().unwrap_or(usize::MAX),
            max_transfer_sizes: spi.get_max_transfer_sizes().unwrap_or(MaxSizes {
                read: 1024,
                write: 1024,
            }),
        };
        let encoding_config = SpiBitbangConfig {
            cpol: config.transfer_mode.polarity() == ClockPolarity::IdleHigh,
            cpha: config.transfer_mode.phase() == ClockPhase::SampleTrailing,
            data_mode: config.data_mode,
            bits_per_word: config.bits_per_word,
        };
        // TODO: there is currently no way to query the underlying SPI's delays
        let encoding_delays = SpiEncodingDelays {
            inter_word_delay: 0,
            // 8 clock cycles between driving CS and first / last SPI words
            cs_hold_delay: 8,
            cs_release_delay: 8,
        };
        pins.setup(encoding_config.data_mode, config.transfer_mode)?;
        let wrapper = SpiBitbangInterface {
            config,
            pins,
            cs_asserted_count: 0,
            encoder: SpiBitbangEncoder::new(encoding_config.clone(), encoding_delays),
            decoder: SpiBitbangDecoder::new(encoding_config, SpiEndpoint::Host),
        };
        Ok(Self {
            underlying: spi,
            wrapper: RefCell::new(wrapper),
        })
    }
}

impl Target for BitbangWrapperSpi {
    fn get_transfer_mode(&self) -> Result<TransferMode> {
        Ok(self.wrapper.borrow().config.transfer_mode)
    }

    fn set_transfer_mode(&self, mode: TransferMode) -> Result<()> {
        match self.underlying.set_transfer_mode(mode) {
            Ok(r) => {
                self.wrapper.borrow_mut().config.transfer_mode = mode;
                Ok(r)
            }
            Err(err) => Err(err),
        }
    }

    fn get_bits_per_word(&self) -> Result<u32> {
        Ok(self.wrapper.borrow().config.bits_per_word)
    }

    fn set_bits_per_word(&self, bits_per_word: u32) -> Result<()> {
        match self.underlying.set_bits_per_word(bits_per_word) {
            Ok(r) => {
                self.wrapper.borrow_mut().config.bits_per_word = bits_per_word;
                Ok(r)
            }
            Err(err) => Err(err),
        }
    }

    fn get_max_speed(&self) -> Result<u32> {
        Ok(self.wrapper.borrow().config.max_speed)
    }

    fn set_max_speed(&self, max_speed: u32) -> Result<()> {
        match self.underlying.set_max_speed(max_speed) {
            Ok(r) => {
                self.wrapper.borrow_mut().config.max_speed = max_speed;
                Ok(r)
            }
            Err(err) => Err(err),
        }
    }

    fn supports_bidirectional_transfer(&self) -> Result<bool> {
        self.underlying.supports_bidirectional_transfer()
    }

    fn supports_tpm_poll(&self) -> Result<bool> {
        Ok(false)
    }

    fn get_max_transfer_count(&self) -> Result<usize> {
        Ok(self.wrapper.borrow().config.max_transfer_count)
    }

    fn get_max_transfer_sizes(&self) -> Result<MaxSizes> {
        Ok(self.wrapper.borrow().config.max_transfer_sizes)
    }

    fn run_transaction(&self, transaction: &mut [Transfer]) -> Result<()> {
        let bidirectional_support = self.supports_bidirectional_transfer().unwrap_or(false);
        self.wrapper
            .borrow_mut()
            .run_transaction(transaction, bidirectional_support)
    }

    fn assert_cs(self: Rc<Self>) -> Result<AssertChipSelect> {
        self.wrapper.borrow_mut().do_assert_cs(true)?;
        Ok(AssertChipSelect::new(self))
    }

    fn set_pins(
        &self,
        _serial_clock: Option<&Rc<dyn GpioPin>>,
        _host_out_device_in: Option<&Rc<dyn GpioPin>>,
        _host_in_device_out: Option<&Rc<dyn GpioPin>>,
        _chip_select: Option<&Rc<dyn GpioPin>>,
        _gsc_ready: Option<&Rc<dyn GpioPin>>,
    ) -> Result<()> {
        if _gsc_ready.is_some() {
            bail!(SpiError::InvalidPin);
        }
        self.wrapper.borrow_mut().set_pins(
            _serial_clock,
            _host_out_device_in,
            _host_in_device_out,
            _chip_select,
        )
    }

    // TODO: add `run_eeprom_transaction` support with Dual/Quad SPI options
    // when Hyperdebug firmware issues are
}

impl TargetChipDeassert for BitbangWrapperSpi {
    fn deassert_cs(&self) {
        // Panic on error, as we cannot propagate errors through `Drop::drop()`
        self.wrapper
            .borrow_mut()
            .do_assert_cs(false)
            .expect("Error while deasserting CS");
    }
}

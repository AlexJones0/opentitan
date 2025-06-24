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

use anyhow::{bail, ensure, Result};
use thiserror::Error;

use crate::io::gpio::{BitbangEntry, GpioPin, PinMode, PullMode};
use crate::io::gpio::{Edge, GpioBitbanging};
use crate::io::spi::{
    AssertChipSelect, ClockPhase, ClockPolarity, MaxSizes, SpiError, Target, TargetChipDeassert, Transfer, TransferMode,
};
use crate::test_utils::bitbanging::spi::{SpiDataMode, SpiBitbangConfig, SpiBitbangDecoder, SpiBitbangEncoder};
use crate::transport::{Transport, TransportError};

#[derive(Error, Debug, PartialEq)]
pub enum SpiBitbangError {
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
        })
    }

    // Configure pinmux to allow SPI bitbanging.
    // Only supports single data transfer mode for now (no dual/quad SPI).
    fn setup(&mut self, transfer_mode: TransferMode) -> Result<()> {
        let clk_idle_level = transfer_mode.polarity() == ClockPolarity::IdleHigh;
        self.sck.set(
            Some(PinMode::PushPull),
            Some(clk_idle_level),  // Match CPOL configuration
            Some(PullMode::PullUp),
            None,
        );
        self.cs.set(
            Some(PinMode::PushPull),
            Some(true),  // CS is active-low
            Some(PullMode::PullUp),
            None,
        );
        self.copi.set_mode(PinMode::PushPull);
        self.cipo.set_mode(PinMode::Input);
        Ok(())
    }

    fn assert_cs(&mut self, assert: bool) -> Result<()> {
        self.cs.write(!assert) // CS is active-low
    }

    /// Bitbang a waveform on the SPI pins. This function will block if
    /// `gpio_bitbanging.run()` blocks. The bitbanging/sampling behaviour depends
    /// on the `BitbangEntry` type provided.
    fn bitbang(&self, samples: BitbangEntry, clock_rate: u32) -> Result<()> {
        // 2 samples per clock (falling & rising edge), so the bitbanging
        // waveform `clock_tick` should be half the SPI clock period.
        let period = Duration::from_nanos((1_000_000_000u64 / clock_rate as u64) / 2);
        let waveform = Box::new([samples]);
        let mut gpio_pins = Vec::from([
            self.sck.borrow(),
            self.cs.borrow(),
            self.copi.borrow(),
            self.cipo.borrow(),
        ]);
        if let Some(data_pins) = &self.d2_3 {
            gpio_pins.push(data_pins[0].borrow());
            gpio_pins.push(data_pins[1].borrow());
        }
        self.gpio_bitbanging.run(&gpio_pins, period, waveform)?;
        Ok(())
    }
}

/// Configurable SPI options
#[derive(Debug)]
struct SpiConfiguration {
    transfer_mode: TransferMode,
    bits_per_word: u32,
    max_speed: u32,
    max_transfer_count: usize,
    max_transfer_sizes: MaxSizes,
    // TODO: how can I tell if the underling SPI target supports setting voltage?
    // Is there a way I can determine this through the GpioPin interface? Since
    // I know I can set voltage there. And can this be used with the GpioBitbanging
    // interface?
}

/// Stateful implementation of the bitbang SPI, separated for clearer
/// interior mutability.
struct SpiBitbangInterface {
    config: SpiConfiguration,
    pins: SpiPins,
    cs_asserted_count: u32,
    encoder: SpiBitbangEncoder<2,3,4,5,0,1>,
    decoder: SpiBitbangDecoder<2,3,4,5,0,1>,
}

impl SpiBitbangInterface {
    /// Request assertion/deassertion of the Chip Select
    fn do_assert_cs(&mut self, assert: bool) -> Result<()> {
        if assert {
            if self.cs_asserted_count == 0 {
                self.pins.assert_cs(true);
            }
            self.cs_asserted_count += 1;
        } else {
            if self.cs_asserted_count == 1 {
                self.pins.assert_cs(false);
            }
            self.cs_asserted_count -= 1;
        }
        Ok(())
    }

    fn get_clock_rate(&self) -> u32 {
        // TODO test and figure out what bitbanging supports well.
        // For now just try to run at 50 kHz.
        const max_bitbang_rate: u32 = 50_000;
        if self.config.max_speed < max_bitbang_rate { 
            self.config.max_speed 
        } else {
            max_bitbang_rate
        }
    }

    fn run_transaction(&self, transaction: &mut [Transfer], supports_bidirectional: bool) -> Result<()> {
        let mut samples = vec![];
        let mut reads = vec![];
        
        self.encoder.cs_active(true, &mut samples);
        for transfer in transaction {
            match transfer {
                Transfer::Write(wbuf) => {
                    ensure!(
                        wbuf.len() <= self.config.max_transfer_sizes.write,
                        SpiError::InvalidDataLength(wbuf.len())
                    );
                    self.encoder.run(wbuf, false, &mut samples);
                }
                Transfer::Read(rbuf) => {
                    ensure!(
                        rbuf.len() <= self.config.max_transfer_sizes.read,
                        SpiError::InvalidDataLength(rbuf.len())
                    );
                    let read_start = samples.len();
                    let bytes_per_word = self.config.bits_per_word.div_ceil(8) as usize;
                    let words = rbuf.len().div_ceil(bytes_per_word);
                    self.encoder.encode_read(words, false, &mut samples);
                    let read_end = samples.len() - 1;
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
                        rbuf.len() <= self.config.max_transfer_sizes.read && wbuf.len() <= self.config.max_transfer_sizes.write,
                        SpiError::InvalidDataLength(wbuf.len())
                    );
                    let read_start = samples.len();
                    self.encoder.run(wbuf, false, &mut samples);
                    let read_end = samples.len() - 1;
                    reads.push((rbuf, read_start, read_end));
                }
                Transfer::TpmPoll => bail!(TransportError::UnsupportedOperation),
                Transfer::GscReady => bail!(TransportError::UnsupportedOperation),
            }
        }
        self.encoder.cs_active(false, &mut samples);

        let clock_rate = self.get_clock_rate();
        if reads.is_empty() {
            self.pins.bitbang(BitbangEntry::Write(&samples), clock_rate)?;
        } else {
            // TODO: len here is + 1? If so, what about read indexes? Need to 
            // make sure this is matched up
            // TODO: maybe use the `BothOwned` interface instead?
            let mut read_samples = Vec::with_capacity(samples.len() + 1);
            let waveform = BitbangEntry::Both(&samples, &mut read_samples);
            self.pins.bitbang(waveform, clock_rate)?;
            for (rbuf, start, end) in reads {
                let decoded = self.decoder.run(read_samples[start..=end].to_vec())?;
                ensure!(
                    decoded.len() == rbuf.len(),
                    SpiBitbangError::MismatchedDecodingLength(decoded.len(), rbuf.len())
                );
                let mut decoded = decoded.iter();
                for byte in rbuf.iter_mut() {
                    let Some(rx) = decoded.next() else {
                        break;
                    };
                    *byte = *rx;
                }
            }
        }

        // TODO finish and remove this comment

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
            bits_per_word: spi.get_bits_per_word().unwrap_or(8),
            max_speed: spi.get_max_speed().unwrap_or(50_000),
            max_transfer_count: spi.get_max_transfer_count().unwrap_or(usize::MAX),
            max_transfer_sizes: spi.get_max_transfer_sizes().unwrap_or(MaxSizes {
                read: 1024,
                write: 1024,
            }),
        };
        // TODO: we have no way to know what the underyling SPI speed is, so we
        // use a speed suitable for bitbanging that conforms to `max_speed`.
        // TODO: for now, we don't have a way of knowing if the underlying SPI is using
        // single/dual/quad data mode, so stick to using single mode for now.
        let encoding_config = SpiBitbangConfig {
            cpol: config.transfer_mode.polarity() == ClockPolarity::IdleHigh,
            cpha: config.transfer_mode.phase() == ClockPhase::SampleTrailing,
            data_mode: SpiDataMode::Single,
            bits_per_word: config.bits_per_word,
            wait_cycles: 8,  // TODO: how do we query this? Default to 8 for now.
        };
        pins.setup(config.transfer_mode)?;
        let wrapper = SpiBitbangInterface {
            config,
            pins,
            cs_asserted_count: 0,
            encoder: SpiBitbangEncoder::new(encoding_config.clone()),
            decoder: SpiBitbangDecoder::new(encoding_config),
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
        Ok(false) // TODO: say no for now to simplify, but consider if we can do this later.
    }

    fn get_max_transfer_count(&self) -> Result<usize> {
        Ok(self.wrapper.borrow().config.max_transfer_count)
    }

    fn get_max_transfer_sizes(&self) -> Result<MaxSizes> {
        Ok(self.wrapper.borrow().config.max_transfer_sizes)
    }

    fn run_transaction(&self, transaction: &mut [Transfer]) -> Result<()> {
        unimplemented!(); // TODO
    }

    fn assert_cs(self: Rc<Self>) -> Result<AssertChipSelect> {
        self.wrapper.borrow_mut().do_assert_cs(true)?;
        Ok(AssertChipSelect::new(self))
    }

    // TODO others: `set_pins`, `set_voltage`, `get_eeprom_max_transfer_sizes`, `run_eeprom_transactions`
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

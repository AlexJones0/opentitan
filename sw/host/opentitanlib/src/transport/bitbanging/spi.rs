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
use thiserror::Error;

use crate::io::gpio::{BitbangEntry, GpioPin, PinMode, PullMode};
use crate::io::gpio::{Edge, GpioBitbanging};
use crate::io::spi::{
    AssertChipSelect, MaxSizes, Target, TargetChipDeassert, Transfer, TransferMode,
};
//use crate::test_utils::bitbanging::spi;
use crate::transport::Transport;

#[derive(Error, Debug, PartialEq)]
pub enum SpiBitbangError {
    #[error("No errors for now")]
    StubError,
}

/// Information related to bitbanging/sampling SPI pins.
pub struct SpiPins {
    sck: Rc<dyn GpioPin>,
    copi: Rc<dyn GpioPin>,              // Host out, device in
    cipo: Rc<dyn GpioPin>,              // Host in, device out
    d2_3: Option<[Rc<dyn GpioPin>; 2]>, // Extra data lines for Quad SPI
    cs: Rc<dyn GpioPin>,
    gsc_ready: Option<Rc<dyn GpioPin>>,
    gpio_bitbanging: Rc<dyn GpioBitbanging>,
}

impl SpiPins {
    pub fn new(
        sck: Rc<dyn GpioPin>,
        copi: Rc<dyn GpioPin>,
        cipo: Rc<dyn GpioPin>,
        cs: Rc<dyn GpioPin>,
        d2_3: Option<[Rc<dyn GpioPin>; 2]>,
        gsc_ready: Option<Rc<dyn GpioPin>>,
        transport: Rc<dyn Transport>,
    ) -> Result<Self> {
        Ok(Self {
            sck,
            copi,
            cipo,
            cs,
            d2_3,
            gsc_ready,
            gpio_bitbanging: transport.gpio_bitbanging()?,
        })
    }

    // Configure pinmux to allow SPI bitbanging.
    fn setup(&mut self) -> Result<()> {
        // TODO
        Ok(())
    }

    fn assert_cs(&mut self, assert: bool) -> Result<()> {
        self.cs.write(!assert) // CS is active-low
    }

    // TODO
}

/// Configurable SPI options
#[derive(Debug)]
struct SpiConfiguration {
    transfer_mode: TransferMode,
    bits_per_word: u32,
    max_speed: u32,
    supports_bidirectional: bool,
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
    // TODO
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
            supports_bidirectional: spi.supports_bidirectional_transfer().unwrap_or(false),
            max_transfer_count: spi.get_max_transfer_count().unwrap_or(usize::MAX),
            max_transfer_sizes: spi.get_max_transfer_sizes().unwrap_or(MaxSizes {
                read: 1024,
                write: 1024,
            }),
        };
        pins.setup()?;
        let wrapper = SpiBitbangInterface {
            config,
            pins,
            cs_asserted_count: 0,
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
        Ok(self.wrapper.borrow().config.supports_bidirectional)
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

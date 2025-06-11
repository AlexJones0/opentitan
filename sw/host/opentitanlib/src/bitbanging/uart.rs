// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serialport::Parity;
use thiserror::Error;

// Configuration to use for UART bitbanging
#[derive(Clone)]
pub struct UartBitbangConfig {
    data_bits: u8,  // Currently assumes <= 8 data bits
    stop_bits: u8,
    // The number of character cycles for which RX is held low during
    // transmission of a break character
    break_char_cycles: u8, 
    parity: Parity,
}

impl UartBitbangConfig {
    pub fn new(data_bits: u8, stop_bits: u8, break_char_cycles: u8, parity: Parity) -> Result<UartBitbangConfig> {
        if data_bits < 5 || data_bits > 8 {
            bail!("UART bitbanging encoder only supports between 5 and 8 bit data.");
        }
        if stop_bits == 0 || stop_bits > 2 {
            bail!("UART bitbanging encoder only supports 1 or 2 stop bits.");
        }
        Ok(Self { data_bits, stop_bits, break_char_cycles, parity })
    }

    // The amount of samples / bit transmissions to transmit one character.
    pub fn bit_time_per_char(&self) -> u32 {
        let parity_bit_count = (self.parity != Parity::None) as u8;
        (1 + self.data_bits + self.stop_bits + parity_bit_count).into()
    }

    // Hold logic low for: (start bit + data bits + parity) * break_cycles
    pub fn break_bit_time(&self) -> u32 {
        self.bit_time_per_char() * self.break_char_cycles as u32
    }
}

// Contains all the errors that can occur when decoding bitbanged UART transfers.
#[derive(Error, Debug, PartialEq, Serialize, Deserialize)]
pub enum UartTransferDecodeError {
    #[error("Computed parity does not match expected parity")]
    ParityMismatch,
    #[error("Stop was not held high for the full stop time")]
    InvalidStop,
    #[error("Frame was held low too long for a valid transmission, but not long enough for a break condition")]
    InvalidBreak,
}


// Possible Uart "Transfers" produced by encoding/decoding waveforms.
#[derive(Debug, PartialEq)]
pub enum UartTransfer {
    // Currently assumed <= 8 data bits.
    Byte { data: u8 },
    Broken { data: u8, parity: Option<bool>, error: UartTransferDecodeError },
    Break,
}

pub struct UartBitbangEncoder<const TX: u8> {
    config: UartBitbangConfig,
}

impl<const TX: u8> UartBitbangEncoder<TX> {

    // Constructor to create a UART bitbanging encoder.
    pub fn new(config: UartBitbangConfig) -> Result<Self> {
        Ok(Self { config })
    }

    // Encode the transmission of a UART break condition into a bitbanging
    // sample, to be used on the TX pin. 
    pub fn encode_break(&self, samples: &mut Vec<u8>) {
        for _ in 0..self.config.break_bit_time() {
            samples.push(0x00 << TX);
        }
    }

    // Encode the transmission of a character into UART bitbanging samples, to
    // be used on the TX pin. This includes a start bit, 5-8 data bits (configured
    // in the encoder), optional parity, and optional stop bits. When configured to
    // use X data bits, only the X LSBs of `char` will be used.
    pub fn encode_character(&self, character: &UartTransfer, samples: &mut Vec<u8>) -> Result<()> {
        let mut data: u8 = 0x00;
        match *character {
            UartTransfer::Broken { .. } => bail!("Cannot encode a broken UART transfer"),
            UartTransfer::Break => {
                self.encode_break(samples);
                return Ok(());
            }
            UartTransfer::Byte { data: char_data } => {
                data = char_data;
            }
        }
        
        // Start bit
        samples.push(0x0 << TX);
        
        // Data bits
        for bit_index in 0..self.config.data_bits {
            let bit = (data >> bit_index) & 0x01;
            samples.push(bit << TX);
        }
        
        // Parity bit (if applicable)
        let parity_bit = data.count_ones() % 2;
        match self.config.parity {
            Parity::Even => { samples.push(((parity_bit != 0) as u8) << TX) },
            Parity::Odd => { samples.push(((parity_bit == 0) as u8) << TX) },
            Parity::None => (),
        }

        // Stop bits
        for _ in 0..self.config.stop_bits {
            samples.push(0x01 << TX);
        }
        Ok(())
    }

    // Helper function to encode multiple characters/breaks into UART
    // bitbanging samples at once.
    pub fn encode_characters(&self, chars: &[UartTransfer], samples: &mut Vec<u8>) -> Result<()> {
        for char in chars {
            self.encode_character(char, samples)?;
        }
        Ok(())
    }
}

// Possible states for the decoder state machine to be in after reading samples.
#[derive(Debug, PartialEq)]
enum DecodingState {
    Idle,
    Data { bits: u8 },
    Parity,
    Stop { data: u8, bits: u8 },
    Break { bits: u32 },
}

pub struct UartBitbangDecoder<const RX: u8> {
    config: UartBitbangConfig,
    state: DecodingState,
    data: u8,
    parity: Option<bool>,
}

impl<const RX: u8> UartBitbangDecoder<RX> {

    // Constructor to create a UART bitbanging decoder.
    pub fn new(config: UartBitbangConfig) -> Result<Self> {
        Ok(Self { 
            config: config,
            state: DecodingState::Idle,
            data: 0x00,
            parity: None,
        })
    }

    // Completes the decoding of the UART character transmission using the
    // current state stored in the decoder.
    fn get_decoded_character(&mut self) -> Result<UartTransfer> {

        // Detect valid & invalid break conditions
        if let DecodingState::Break {bits} = self.state {
            if bits < self.config.break_bit_time() {
                return Ok(UartTransfer::Broken {
                    data: self.data,
                    parity: self.parity,
                    error: UartTransferDecodeError::InvalidBreak,
                });
            }
            return Ok(UartTransfer::Break);
        }

        // Check we've fully stopped first, and record broken transmissions due
        // to invalid stop signals.
        if let DecodingState::Stop {data, bits} = self.state {
            if bits != self.config.stop_bits {
                bail!("`get_decoded_character` called before reading all stop bits");
            }
            for bit_index in 0..bits {
                if (data >> bit_index) & 0x01 != 0x01 {
                    return Ok(UartTransfer::Broken { 
                        data: self.data, 
                        parity: self.parity, 
                        error: UartTransferDecodeError::InvalidStop,
                    });
                }
            }
        } else {
            bail!("`get_decoded_character` called before the end of a transmission");
        }

        // If configured to use parity, check and report single parity errors.
        if self.config.parity != Parity::None {
            let mut decoded_parity = (self.data.count_ones() % 2) != 0;
            if let Some(parity_bit) = self.parity {
                decoded_parity ^= parity_bit;
            }

            let expected_parity = self.config.parity != Parity::Even;
            if expected_parity ^ decoded_parity {
                return Ok(UartTransfer::Broken {
                    data: self.data,
                    parity: self.parity,
                    error: UartTransferDecodeError::ParityMismatch
                });
            }
        }

        // If there are no stop or parity issues, decode the character
        return Ok(UartTransfer::Byte { data: self.data });
    }

    // Given a GPIO sample (where bit RX is our UART TX sample), advance the
    // UART bitbanging decoder state machine based on the contents of that
    // sample. If this sample is the final stop bit, return the decoded
    // UART transfer.
    pub fn decode_sample(&mut self, sample: u8) -> Result<Option<UartTransfer>> {
        let rx = (sample >> RX) & 0x1;
        match self.state {
            DecodingState::Idle => {
                if rx == 0 {
                    self.data = 0x00;
                    self.state = DecodingState::Data { bits: 0 };
                }
            }
            DecodingState::Data { bits } => {
                self.data = self.data | (rx << bits);
                let bits = bits + 1;
                if bits >= self.config.data_bits {
                    if self.config.parity == Parity::None {
                        self.state = DecodingState::Stop { data: 0x00, bits: 0 };
                    } else {
                        self.state = DecodingState::Parity;
                    }
                } else {
                    self.state = DecodingState::Data { bits };
                }
            }
            DecodingState::Parity => {
                self.parity = Some(rx != 0);
                self.state = DecodingState::Stop { data: 0x00, bits: 0 };
            }
            DecodingState::Stop { data, bits } => {
                let data = data | (rx << bits);
                let bits = bits + 1;
                self.state = DecodingState::Stop { data, bits };
                if bits >= self.config.stop_bits {
                    if self.data != 0x00 || self.parity != Some(false) || data != 0x00 {
                        let decoded = self.get_decoded_character()?;
                        self.state = DecodingState::Idle;
                        return Ok(Some(decoded));
                    }
                    self.state = DecodingState::Break {
                        bits: (1 + self.config.data_bits + self.config.stop_bits).into()
                    };
                }
            }
            DecodingState::Break { bits } => {
                self.state = DecodingState::Break { bits: bits + 1 };
                if rx != 0 {
                    let decoded = self.get_decoded_character()?;
                    self.state = DecodingState::Idle;
                    return Ok(Some(decoded));
                }
            }
        }
        Ok(None)
    }

    // A helper function to decode multiple GPIO samples at once, advancing
    // the UART bitbanging decoder state machine based on the contents of those
    // samples. Depending on the number of samples, this may return no transfers
    // (an empty vec) or many transfers. 
    pub fn decode_samples(&mut self, samples: &Vec<u8>) -> Result<Vec<UartTransfer>> {
        let mut trans = vec![];
        for sample in samples {
            if let Some(Transfer) = self.decode_sample(*sample)? {
                trans.push(Transfer);
            }
        }
        Ok(trans)
    }

    // Check if the decoder is currently in the idle state or not
    pub fn is_idle(&self) -> bool {
        self.state == DecodingState::Idle
    }

    // Reset the state of decoder.
    pub fn reset(&mut self) {
        self.state = DecodingState::Idle;
        self.data = 0x00;
        self.parity = None;
    }
}
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::app::TransportWrapper;
use crate::debug::dmi::{Dmi, OpenOcdDmi};
use crate::io::jtag::{JtagChain, JtagParams, JtagTap};
use crate::transport::Capability;
use crate::util::vmem::Word;

/// FPGA Backdoor loader register offsets (byte-addressed) and field definitions.
/// See hw/ip/bkdr_loader/doc/registers.md
/// TODO: it would be nice to use Bazel to auto-generate a rust "header" for this IP instead.
pub mod regs {

    // STATUS register
    pub const STATUS_REG_OFFSET: usize = 0x0;
    pub const STATUS_ERROR_BIT: u32 = 0;

    // CONTROL register
    pub const CONTROL_REG_OFFSET: usize = 0x4;
    pub const CONTROL_DONE_BIT: u32 = 0;
    pub const CONTROL_WRITE_ENA_BIT: u32 = 1;
    pub const CONTROL_TARGET_IDX_MASK: u32 = 0xff;
    pub const CONTROL_TARGET_IDX_OFFSET: usize = 8;

    // Other registers (all have one 32-bit `VAL` field)
    pub const NUM_BKDR_TARGETS_REG_OFFSET: usize = 0x8;
    pub const USR_ACCESS_TIMESTAMP_REG_OFFSET: usize = 0xc;
    pub const TARGET_INFO_0_REG_OFFSET: usize = 0x100;
    pub const WIDTH_INFO_0_REG_OFFSET: usize = 0x200;
    pub const DEPTH_INFO_0_REG_OFFSET: usize = 0x300;
    pub const READ_DATA_0_REG_OFFSET: usize = 0x400;
    pub const WRITE_DATA_0_REG_OFFSET: usize = 0x500;
    pub const INDEX_REG_OFFSET: usize = 0x600;

    // Parameters - see hw/ip/bkdr_loader/doc/interfaces.md
    pub const MAX_NUM_TARGETS: usize = 12; // NumBkdrTargets
    pub const DATA_REGS_PER_WORD: usize = 8; // MaxWordWidthDiv32
}

/// Apply the bkdr_loader TAP strapping and reset to enter the backdoor loader.
pub fn enter_backdoor_loader(transport: &TransportWrapper) -> Result<()> {
    transport.capabilities()?.request(Capability::GPIO).ok()?;
    let pinmux_tap_bkdr = transport.pin_strapping("PINMUX_TAP_BKDR")?;
    let reset = transport.pin_strapping("RESET")?;

    pinmux_tap_bkdr.apply()?;
    reset.apply()?;
    reset.remove()?;
    pinmux_tap_bkdr.remove()?;

    Ok(())
}

/// A struct which represents a backdoor loader interface.
///
/// This struct represents an adaptor that has been configured to connect to a given JTAG chain,
/// but has not yet been configured to access the backdoor TAP.
pub struct BackdoorTap<'a> {
    jtag: Box<dyn JtagChain + 'a>,
}

impl BackdoorTap<'_> {
    /// Connect to the backdoor TAP, optionally enumerate information about all targets.
    pub fn connect(self, enumerate: bool) -> Result<Backdoor> {
        let openocd = self.jtag.connect(JtagTap::BackdoorTap)?.into_raw()?;
        Backdoor::new(OpenOcdDmi::new(openocd, "bkdr.tap")?, enumerate)
    }
}

#[derive(Debug, Args, Clone)]
pub struct BackdoorParams {
    /// JTAG options to apply to the backdoor TAP.
    #[command(flatten)]
    pub jtag: JtagParams,
}

impl BackdoorParams {
    pub fn create<'a>(&self, transport: &'a TransportWrapper) -> Result<BackdoorTap<'a>> {
        Ok(BackdoorTap {
            jtag: self.jtag.create(transport)?,
        })
    }
}

/// Information about a specific backdoor target, e.g. OTP, ROM, FB0, SRAM.
#[derive(Debug, Clone, Copy)]
pub struct BackdoorTargetInfo {
    /// The unique identifier of the backdoor target
    pub id: u32,
    /// The word width of the memory of the backdoor target.
    pub width: u32,
    /// The depth (number of words) of the memory of the backdoor target.
    pub depth: u32,
}

impl BackdoorTargetInfo {
    /// The target's unique identifier as a <= 4 character UTF-8 string.
    pub fn id_str(&self) -> String {
        let bytes = self.id.to_be_bytes();

        String::from_utf8_lossy(&bytes).trim_end().to_owned()
    }

    // Convert a UTF-8 ID string into the unique u32 identifier format used by targets.
    pub fn id_from_str(id: &str) -> Result<u32> {
        let mut bytes = [32u8; 4];
        let src = id.as_bytes();
        let len = id.len().min(4);
        bytes[..len].copy_from_slice(&src[..len]);

        Ok(u32::from_be_bytes(bytes))
    }
}

impl Serialize for BackdoorTargetInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("BackdoorTargetInfo", 4)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("id_str", &self.id_str())?;
        s.serialize_field("width", &self.width)?;
        s.serialize_field("depth", &self.depth)?;
        s.end()
    }
}

impl std::fmt::Display for BackdoorTargetInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {} x {}", self.id_str(), self.width, self.depth)
    }
}

impl Word {
    /// Convert the word to a series of 32-bit chunks to be written to the data registers.
    fn to_u32_chunks(&self) -> Result<[u32; regs::DATA_REGS_PER_WORD]> {
        ensure!(
            self.bytes.len() <= regs::DATA_REGS_PER_WORD * 4,
            "Word '{}' with {} bytes will not fit into {} 32-bit registers.",
            hex::encode(self.bytes.clone()),
            self.bytes.len(),
            regs::DATA_REGS_PER_WORD
        );
        let mut chunks = [0u32; regs::DATA_REGS_PER_WORD];

        // Bytes are stored in Big Endian; when written to registers, the u32
        // chunks are provided in LSB-first order (Little Endian).
        for (i, &b) in self.bytes.iter().rev().enumerate() {
            // Within u32 chunks, bytes are still given in MSB-first order (Big Endian).
            let chunk_idx = i / 4;
            let byte_pos = i % 4;
            chunks[chunk_idx] |= (b as u32) << (byte_pos * 8);
        }

        Ok(chunks)
    }

    /// Convert the 32-bit chunks read from data registers into a word (MSB-first byte stream).
    fn from_u32_chunks(chunks: &[u32; regs::DATA_REGS_PER_WORD], bytes_per_word: usize) -> Self {
        let mut bytes = vec![0u8; bytes_per_word];
        for (i, byte) in bytes.iter_mut().rev().enumerate() {
            let chunk_idx = i / 4;
            let byte_pos = i % 4;
            *byte = (chunks[chunk_idx] >> (byte_pos * 8)) as u8;
        }

        Self { bytes }
    }
}

/// Handle for interacting with a given target via the backdoor loader.
pub struct BackdoorTarget<'a> {
    backdoor: &'a mut Backdoor,
    index: u8,
    /// Information about the target.
    pub info: BackdoorTargetInfo,
}

impl<'a> BackdoorTarget<'a> {
    /// Write a sequence of words at a given offset (word index) in the target's memory.
    ///
    /// The `write_all` parameter is used to control whether writes can be optimized by
    /// maintaining shadow CSRs to determine when register contents have genuinely changed.
    /// The `check_status` parameter is used to control whether the status bit is polled
    /// after all words are written, to check for any errors.
    pub fn write(
        &mut self,
        start: u32,
        words: &[Word],
        write_all: bool,
        check_status: bool,
    ) -> Result<()> {
        if start + words.len() as u32 > self.info.depth {
            bail!(
                "fpga bkdr_loader write of len {:#x} to word {:#x} of {} is out of bounds (depth: {:#x})",
                words.len(),
                start,
                self.info.id_str(),
                self.info.depth
            );
        }
        self.backdoor
            .write_target(self.index, start, words, write_all, check_status)
    }

    /// Read a sequence of words at a given offset (word index) from the target's memory.
    ///
    /// The `check_status` parameter is used to control whether the status bit is polled
    /// after each word read, to check for any errors.
    pub fn read(&mut self, start: u32, count: u32, check_status: bool) -> Result<Vec<Word>> {
        if start + count > self.info.depth {
            bail!(
                "fpga bkdr_loader read of len {:#x} to word {:#x} of {} is out of bounds (depth: {:#x})",
                count,
                start,
                self.info.id_str(),
                self.info.depth
            );
        }
        self.backdoor
            .read_target(self.index, start, count, check_status)
    }
}

/// A struct which represents an active backdoor loader connection.
pub struct Backdoor {
    dmi: OpenOcdDmi,
    targets: Vec<BackdoorTargetInfo>,
}

impl Backdoor {
    /// Construct a [`Backdoor`] from a DMI connection to the backdoor TAP. Optionally
    /// enumerate and discover information about all available targets.
    pub fn new(dmi: OpenOcdDmi, enumerate: bool) -> Result<Self> {
        let mut fpga_bkdr = Self {
            dmi,
            targets: Vec::new(),
        };
        if enumerate {
            fpga_bkdr.enumerate()?;
        }

        Ok(fpga_bkdr)
    }

    /// Read from a DMI register with the given byte address offset.
    /// DMI is a register interface; we must map the byte offsets to register (word) index.
    fn dmi_read(&mut self, byte_addr: usize) -> Result<u32> {
        self.dmi.dmi_read(byte_addr as u32 >> 2)
    }

    /// Write a value to a DMI register with the given byte address offset.
    /// DMI is a register interface; we must map the byte offsets to register (word) index.
    fn dmi_write(&mut self, byte_addr: usize, data: u32) -> Result<()> {
        self.dmi.dmi_write(byte_addr as u32 >> 2, data)
    }

    // Enumerate the backdoor loader and retrieve information about available targets.
    pub fn enumerate(&mut self) -> Result<()> {
        self.targets.clear();

        let num_targets = self
            .dmi_read(regs::NUM_BKDR_TARGETS_REG_OFFSET)
            .context("cannot read number of targets")? as usize;
        log::info!("Number of FPGA bkdr_loader targets: {num_targets:?}");
        for idx in 0..num_targets {
            let addr_offset = idx * 4;
            let target_info = BackdoorTargetInfo {
                id: self
                    .dmi_read(regs::TARGET_INFO_0_REG_OFFSET + addr_offset)
                    .context("cannot read target info")?,
                width: self
                    .dmi_read(regs::WIDTH_INFO_0_REG_OFFSET + addr_offset)
                    .context("cannot read width info")?,
                depth: self
                    .dmi_read(regs::DEPTH_INFO_0_REG_OFFSET + addr_offset)
                    .context("cannot read depth info")?,
            };
            self.targets.push(target_info);
        }

        Ok(())
    }

    /// Communicate with the backdoor loader that we are finished using it.
    ///
    /// This transitions the bkdr_loader from it from its "Preload" state to "Mission mode",
    /// where it will bring the system out of reset and re-route upstream the JTAG.
    pub fn set_done(mut self) -> Result<()> {
        log::debug!("Finished using backdoor loader until next reset");

        // We typically expect to see an error here due to a DMI operation fail. This is
        // because, when our write to `CTRL.DONE` goes through and the bkdr_loader enters
        // mission mode, it immediately switches the routing of the upstream JTAG port
        // back to the downstream JTAG (rather than the internal backdoor DMI).
        // This means that we won't see the expected response - we're now talking to a
        // completely different DMI / DTM.
        let _ = self.dmi_write(regs::CONTROL_REG_OFFSET, 0b1 << regs::CONTROL_DONE_BIT);

        Ok(())
    }

    /// Retrieve information about all of the targets available via the backdoor interface.
    pub fn targets(&self) -> &[BackdoorTargetInfo] {
        &self.targets
    }

    /// Borrow a target by its integer identifier. Only one BackdoorTarget can exist at a time.
    pub fn target_by_id(&mut self, id: u32) -> Option<BackdoorTarget<'_>> {
        let (index, info) = self.targets.iter().enumerate().find(|&(_, t)| t.id == id)?;
        let (index, info) = (index as u8, *info);

        Some(BackdoorTarget {
            backdoor: self,
            index,
            info,
        })
    }

    /// Borrow a target by its string identifier. Only one BackdoorTarget can exist at a time.
    pub fn target_by_id_str(&mut self, id: &str) -> Result<Option<BackdoorTarget<'_>>> {
        let encoded_id = BackdoorTargetInfo::id_from_str(id)?;

        Ok(self.target_by_id(encoded_id))
    }

    /// Write a sequence of words at a given offset (word index) to a specified target's memory.
    ///
    /// The `write_all` parameter is used to control whether writes can be optimized by
    /// maintaining shadow CSRs to determine when register contents have actually changed.
    /// The `check_status` parameter is used to control whether the status bit is polled
    /// after all words are written, to check for any errors.
    pub fn write_target(
        &mut self,
        target_index: u8,
        start: u32,
        words: &[Word],
        write_all: bool,
        check_status: bool,
    ) -> Result<()> {
        let info = self.targets[target_index as usize];
        let width = info.width as usize;
        let regs_used = width.div_ceil(32);
        ensure!(
            regs_used <= regs::DATA_REGS_PER_WORD,
            "Advertised target width {:#x} is too wide for the data registers (needs: {:#x}, has: {:#x})",
            width,
            regs_used,
            regs::DATA_REGS_PER_WORD
        );

        // Cache previous written values in Shadow CSRs
        let mut prev_regs = [0u32; regs::DATA_REGS_PER_WORD];
        let mut word_idx = start;
        let mut first = true;

        let mut control = (target_index as u32) << regs::CONTROL_TARGET_IDX_OFFSET;
        control |= 0b1 << regs::CONTROL_WRITE_ENA_BIT;
        self.dmi_write(regs::CONTROL_REG_OFFSET, control)
            .context("cannot write to control register")?;

        // We batch together all the necessary writes so that we can perform a single
        // batched write operation at the end, which is optimized for throughput.
        let mut writes = Vec::new();

        for word in words {
            let regs = word.to_u32_chunks()?;
            for idx in 0..regs_used {
                // Optimization - maintain shadow CSRs in software, and only write the
                // data if there is a diff in that CSR from the previous contents. Vastly
                // minimizes required operations for repetitive payloads.
                if write_all || first || regs[idx] != prev_regs[idx] {
                    let addr_offset = idx * 4;
                    writes.push((
                        ((regs::WRITE_DATA_0_REG_OFFSET + addr_offset) >> 2) as u32,
                        regs[idx],
                    ));
                    prev_regs[idx] = regs[idx];
                }
            }
            writes.push(((regs::INDEX_REG_OFFSET >> 2) as u32, word_idx));
            first = false;
            word_idx += 1;
        }

        self.dmi
            .batched_dmi_writes(&writes)
            .context("failed to perform DMI writes")?;

        if check_status {
            let status = self
                .dmi_read(regs::STATUS_REG_OFFSET)
                .context("cannot read status")?;
            if status & (0b1 << regs::STATUS_ERROR_BIT) != 0 {
                bail!(
                    "fpga bkdr_loader reported an error writing to target {}",
                    info.id_str()
                );
            }
        }

        Ok(())
    }

    /// Read a sequence of words at a given offset (word index) from a specified target's memory.
    ///
    /// The `check_status` parameter is used to control whether the status bit is polled
    /// after each word read, to check for any errors.
    pub fn read_target(
        &mut self,
        target_index: u8,
        start: u32,
        count: u32,
        check_status: bool,
    ) -> Result<Vec<Word>> {
        let info = self.targets[target_index as usize];
        let width = info.width as usize;
        let bytes_per_word = width.div_ceil(8);
        let regs_used = width.div_ceil(32);
        ensure!(
            regs_used <= regs::DATA_REGS_PER_WORD,
            "Advertised target width {:#x} is too wide for the data registers (needs: {:#x}, has: {:#x})",
            width,
            regs_used,
            regs::DATA_REGS_PER_WORD
        );

        let mut control = (target_index as u32) << regs::CONTROL_TARGET_IDX_OFFSET;
        control |= 0b0 << regs::CONTROL_WRITE_ENA_BIT;
        self.dmi_write(regs::CONTROL_REG_OFFSET, control)
            .context("cannot write to control register")?;

        let mut words = Vec::new();

        for word_idx in start..(start + count) {
            self.dmi_write(regs::INDEX_REG_OFFSET, word_idx)
                .context("cannot write word index")?;

            if check_status {
                let status = self
                    .dmi_read(regs::STATUS_REG_OFFSET)
                    .context("cannot read status")?;
                if status & (0b1 << regs::STATUS_ERROR_BIT) != 0 {
                    bail!(
                        "fpga bkdr_loader reported an error reading from word idx {} of target {}",
                        word_idx,
                        info.id_str()
                    );
                }
            }

            let mut regs = [0u32; regs::DATA_REGS_PER_WORD];
            for (idx, reg) in regs.iter_mut().enumerate().take(regs_used) {
                let addr_offset = idx * 4;
                *reg = self
                    .dmi_read(regs::READ_DATA_0_REG_OFFSET + addr_offset)
                    .context("cannot read from read_data register")?;
            }

            words.push(Word::from_u32_chunks(&regs, bytes_per_word));
        }

        Ok(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifer_str_encoding() {
        let (width, depth) = (1, 1);
        for (id, id_str) in [
            (0x4f545020, "OTP"),
            (0x5352414d, "SRAM"),
            (0x46493031, "FI01"),
        ] {
            assert_eq!(BackdoorTargetInfo { id, width, depth }.id_str(), id_str);
            assert_eq!(BackdoorTargetInfo::id_from_str(id_str).unwrap(), id);
        }
    }

    #[test]
    fn byte_u32_conversion() {
        // Bytes stored in words are Big Endian (MSB first).
        let word = Word::new(vec![
            0x5a, 0xa5, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xbe, 0xef, 0xca, 0xfe,
        ]);
        // Register chunks are Little Endian, but bytes in each u32 are Big Endian.
        // The 4th register should be half-used, the 4 remaining regs should be unused.
        let mut expected = [0x0; regs::DATA_REGS_PER_WORD];
        expected[0] = 0xbeefcafe;
        expected[1] = 0x89abcdef;
        expected[2] = 0x01234567;
        expected[3] = 0x00005aa5;

        let chunks = word.to_u32_chunks().unwrap();
        assert_eq!(chunks, expected);
        assert_eq!(Word::from_u32_chunks(&chunks, word.bytes.len()), word);
    }
}

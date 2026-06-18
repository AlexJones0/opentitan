// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Args;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::app::TransportWrapper;
use crate::debug::dmi::{Dmi, OpenOcdDmi};
use crate::io::jtag::{JtagChain, JtagParams, JtagTap};
use crate::transport::Capability;

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
    jtag: JtagParams,
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

/// Handle for interacting with a given target via the backdoor loader.
pub struct BackdoorTarget {
    /// Information about the target.
    pub info: BackdoorTargetInfo,
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

    /// Borrow a target by its integer identifier.
    pub fn target_by_id(&self, id: u32) -> Option<BackdoorTarget> {
        let info = self.targets.iter().find(|&t| t.id == id)?;

        Some(BackdoorTarget { info: *info })
    }

    /// Borrow a target by its string identifier.
    pub fn target_by_id_str(&self, id: &str) -> Result<Option<BackdoorTarget>> {
        let encoded_id = BackdoorTargetInfo::id_from_str(id)?;

        Ok(self.target_by_id(encoded_id))
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
}

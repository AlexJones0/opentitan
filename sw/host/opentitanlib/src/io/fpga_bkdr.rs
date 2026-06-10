// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Args;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::app::TransportWrapper;
use crate::io::jtag::{JtagChain, JtagParams, JtagTap};
use crate::debug::dmi::{Dmi, OpenOcdDmi};

/// Constants defined by RISC-V Debug Specification 0.13.
pub mod consts {
    // Backdoor registers.
    // Note: register addresses must be divided by 4.
    // TODO ^ reword above comment slightly to explain in more detail
    pub const NUM_BKDR_TARGETS: u32 = 0x2;
    pub const TARGET_INFO_0: u32 = 0x40;
    pub const WIDTH_INFO_0: u32 = 0x80;
    pub const DEPTH_INFO_0: u32 = 0xc0;
}

/// A struct which represents a backdoor loader interface.
///
/// This struct represents an adaptor that has been configured to connect to a given JTAG chain,
/// but has not yet been configured to access the backdoor TAP.
pub struct BackdoorTap<'a> {
    jtag: Box<dyn JtagChain + 'a>,
}

impl BackdoorTap<'_> {
    /// Connect to backdoor TAP.
    pub fn connect(self) -> Result<Backdoor> {
        // TODO: do we need to depend on openocd specifically, or can we use the JTAG
        // abstraction? I think that we probbly to to be able to instantiate an `OpenOcdDmi`,
        // but this seems like a failure of the DMI interface - is it not possible to create
        // a `dyn Dmi` from the `dyn Jtag` abstraction?
        let openocd = self.jtag.connect(JtagTap::BackdoorTap)?.into_raw()?;
        Ok(Backdoor {
            // We expect the bkdr.tap to be configured.
            dmi: OpenOcdDmi::new(openocd, "bkdr.tap")?,
        })
    }
}

#[derive(Debug, Args, Clone)]
pub struct BackdoorParams {
    // We need JTAG parameters to connect to the TAP.
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

/// Information about a specific backdoor target, e.g. OTP, ROM, SRAM.
#[derive(Debug)]
pub struct BackdoorTargetInfo {
    /// The unique identifier for the backdoor target
    pub id: u32,
    /// The word width of the memory of the backdoor target.
    pub width: u32,
    // The depth (number of words) of the memory of the backdoor target.
    pub depth: u32,
}

impl BackdoorTargetInfo {
    pub fn id_str(&self) -> String {
        let bytes = self.id.to_be_bytes();
        // TODO: strict UTF-8 checking instead of lossy?
        String::from_utf8_lossy(&bytes).trim().to_string()
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

use consts::*;

/// A struct which represents a backdoor loader connection
pub struct Backdoor {
    dmi: OpenOcdDmi,
}

impl Backdoor {
    /// Retrieve information about the targets available via the backdoor interface.
    pub fn targets(&mut self) -> Result<Vec<BackdoorTargetInfo>> {
        let mut targets = vec![];
        let num_targets = self.dmi.dmi_read(NUM_BKDR_TARGETS).context("cannot read number of targets")?;
        log::info!("num targets: {num_targets:?}");
        for idx in 0..num_targets {
            targets.push(BackdoorTargetInfo {
                id: self.dmi.dmi_read(TARGET_INFO_0 + idx).context("cannot read target info")?,
                width: self.dmi.dmi_read(WIDTH_INFO_0 + idx).context("cannot read width info")?,
                depth: self.dmi.dmi_read(DEPTH_INFO_0 + idx).context("cannot read depth info")?,
            })
        }

        Ok(targets)
    }
}

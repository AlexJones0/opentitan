// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Args;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::app::TransportWrapper;
use crate::io::jtag::{JtagChain, JtagParams, JtagTap};
use crate::debug::dmi::{Dmi, OpenOcdDmi};

#[derive(Debug, Args, Clone)]
pub struct BkdrParams {
    // We need JTAG parameters to connect to the TAP.
    #[command(flatten)]
    jtag: JtagParams,
}

impl BkdrParams {
    pub fn create<'a>(&self, transport: &'a TransportWrapper) -> Result<BkdrTap<'a>> {
        Ok(BkdrTap {
            jtag: self.jtag.create(transport)?,
        })
    }
}

/// A struct which represents a backdoor loader interface.
///
/// This struct represents an adaptor that has been configured to connect to a given JTAG chain,
/// but have not yet been configured to access the backdoor TAP.
pub struct BkdrTap<'a> {
    jtag: Box<dyn JtagChain + 'a>,
}

impl BkdrTap<'_> {
    /// Connect to backdoor TAP.
    pub fn connect(self) -> Result<Bkdr> {
        let openocd = self.jtag.connect(JtagTap::BkdrTap)?.into_raw()?;
        Ok(Bkdr {
            // We expect the bkdr.tap to be configured.
            dmi: OpenOcdDmi::new(openocd, "bkdr.tap")?,
        })
    }
}

pub struct Bkdr {
    dmi: OpenOcdDmi,
}

#[derive(Debug)]
pub struct BkdrTargetInfo {
    pub id: u32,
    pub width: u32,
    pub depth: u32,
}

impl BkdrTargetInfo {
    pub fn id_str(&self) -> String {
        let mut res = String::new();
        for idx in 0..4 {
            res.push(char::from_u32((self.id >> 8*(3 - idx)) & 0xff).unwrap())
        }
        res.trim().to_string()
    }
}

impl Serialize for BkdrTargetInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("BkdrTargetInfo", 4)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("id_str", &self.id_str())?;
        s.serialize_field("width", &self.width)?;
        s.serialize_field("depth", &self.depth)?;
        s.end()
    }
}

impl std::fmt::Display for BkdrTargetInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {} x {}", self.id_str(), self.width, self.depth)
    }
}

/// Constants defined by RISC-V Debug Specification 0.13.
pub mod consts {
    // Bkdr registers.
    // Note: register addresses must be divided by 4.
    pub const NUM_BKDR_TARGETS: u32 = 0x2;
    pub const TARGET_INFO_0: u32 = 0x40;
    pub const WIDTH_INFO_0: u32 = 0x80;
    pub const DEPTH_INFO_0: u32 = 0xc0;
}

use consts::*;

impl Bkdr {
    pub fn targets(&mut self) -> Result<Vec<BkdrTargetInfo>> {
        let mut targets = vec![];
        let num_targets = self.dmi.dmi_read(NUM_BKDR_TARGETS).context("cannot read number of targets")?;
        log::info!("num targets: {num_targets:?}");
        for idx in 0..num_targets {
            targets.push(BkdrTargetInfo {
                id: self.dmi.dmi_read(TARGET_INFO_0 + idx).context("cannot read target info")?,
                width: self.dmi.dmi_read(WIDTH_INFO_0 + idx).context("cannot read width info")?,
                depth: self.dmi.dmi_read(DEPTH_INFO_0 + idx).context("cannot read depth info")?,
            })
        }

        Ok(targets)
    }
}

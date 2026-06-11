// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::any::Any;
use std::convert::From;

use opentitanlib::app::TransportWrapper;
use opentitanlib::app::command::CommandDispatch;
use opentitanlib::io::fpga_bkdr::{BackdoorParams, Word};

/// Commands for interacting with the backdoor FPGA loader.
#[derive(Debug, Subcommand, CommandDispatch)]
pub enum InternalBkdrCommand {
    /// Enter the backdoor loader - this *requires* resetting the device.
    Enter(EnterInfo),
    /// Display information about the available backdoor targets
    Info(BkdrInfo),
    /// Test write-readback command, to be removed.
    Test(TestInfo),
}

#[derive(Debug, Args)]
pub struct EnterInfo {}

impl CommandDispatch for EnterInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let _bkdr = context.params.create(transport)?;
        // TODO: make a common library as well.
        unimplemented!();
    }
}

#[derive(Debug, Args)]
pub struct BkdrInfo {}

impl CommandDispatch for BkdrInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let bkdr = bkdr.connect()?;
        let targets = bkdr.targets().to_vec();
        Ok(Some(Box::new(targets)))
    }
}

#[derive(Debug, Args)]
pub struct TestInfo {}

impl CommandDispatch for TestInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect()?;
        let mut rom_bkdr = bkdr
            .target_by_id_str("ROM")?
            .context("Could not find ROM target for testing")?;
        rom_bkdr.write(0x0, &[Word(vec![0u8].into_boxed_slice())], false)?;
        println!("{:?}", rom_bkdr.read(0x0, 1)?);
        Ok(None)
    }
}

#[derive(Debug, Args)]
pub struct BkdrCommand {
    #[command(flatten)]
    params: BackdoorParams,

    #[command(subcommand)]
    command: InternalBkdrCommand,
}

impl CommandDispatch for BkdrCommand {
    fn run(
        &self,
        _context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        self.command.run(self, transport)
    }
}

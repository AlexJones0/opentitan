// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::{Args, Subcommand};
use std::any::Any;
use std::convert::From;

use opentitanlib::app::TransportWrapper;
use opentitanlib::app::command::CommandDispatch;
use opentitanlib::io::bkdr::BkdrParams;

/// Commands for interacting with the backdoor loader.
#[derive(Debug, Subcommand, CommandDispatch)]
pub enum InternalBkdrCommand {
    /// Enter the backdoor loader, this requires resetting the device.
    Enter(EnterInfo),
    /// Display information about the backdoor targets.
    Info(BkdrInfo),
}

#[derive(Debug, Args)]
pub struct EnterInfo {
}

impl CommandDispatch for EnterInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let _bkdr = context.params.create(transport)?;
        unimplemented!();
    }
}

#[derive(Debug, Args)]
pub struct BkdrInfo {
}

impl CommandDispatch for BkdrInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect()?;
        let targets = bkdr.targets()?;
        Ok(Some(Box::new(targets)))
    }
}

#[derive(Debug, Args)]
pub struct BkdrCommand {
    #[command(flatten)]
    params: BkdrParams,

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

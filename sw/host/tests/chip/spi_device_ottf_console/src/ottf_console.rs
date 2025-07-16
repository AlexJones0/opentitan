// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;

use opentitanlib::execute_test;

mod common;

fn main() -> Result<()> {
    let opts = common::Opts::parse();
    opts.init.init_logging();
    let transport = opts.init.init_target()?;
    execute_test!(common::spi_device_console_test, &opts, &transport);
    Ok(())
}

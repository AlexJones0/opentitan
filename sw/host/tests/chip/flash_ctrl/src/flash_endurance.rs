// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;

use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::uart::console::UartConsole;

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    init: InitializeTest,

    /// Path to the firmware's ELF file, for querying symbol addresses.
    #[arg(value_name = "FIRMWARE_ELF")]
    firmware_elf: PathBuf,

    /// Users should manually provide this arg to acknowledge that they
    /// understand what the test does and wish to run the test.
    #[arg(long)]
    acknowledge_test_action: bool,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    opts.init.init_logging();

    // Verify user acknowledgement, and print out a desc & exit if not provided.
    if !opts.acknowledge_test_action {
        log::info!(
            "\n\nWARNING: This test intends to wear down physical flash until\n\
             the point of failure. On silicon, this means that the tested pages\n\
             of flash can no longer be reliably used. This test is currently\n\
             designed to wear down the last few pages of bank 1's data partition\n\
             0 that it can reliably write to. For devices other than silicon\n\
             (e.g. FPGA) the number of program/erase cycles is limited to just 5\n\
             to avoid wearing down hardware, but you still must provide user\n\
             acknowledgement to run the test.\n\n\
             If you acknowledge that this test will wear down physical flash and\n\
             would like to proceed running the test, add the following argument\n\
             to your Bazel command line invocation of the test:\n\
               --test_arg=--acknowledge-test-action\n"
        );
        return Err(anyhow!("User acknowledgement not provided."));
    }

    let transport = opts.init.init_target()?;
    let uart = transport.uart("console")?;

    // Await the PASS/FAIL indication from the device-side software.
    let vec = UartConsole::wait_for(&*uart, r"(PASS|FAIL)!", humantime::parse_duration("7d")?)?;
    match vec[0].as_str() {
        "PASS!" => Ok(()),
        _ => Err(anyhow!("Failure result: {:?}", vec)),
    }
}

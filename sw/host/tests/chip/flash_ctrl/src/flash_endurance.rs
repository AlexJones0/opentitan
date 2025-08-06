// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, ensure, Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use opentitanlib::app::TransportWrapper;
use opentitanlib::backend;
use opentitanlib::chip::boot_svc::BootSlot;
use opentitanlib::io::uart::Uart;
use opentitanlib::rescue::serial::RescueSerial;
use opentitanlib::rescue::{EntryMode, Rescue};
use opentitanlib::test_utils::flash::*;
use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::uart::console::UartConsole;

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    init: InitializeTest,

    // Skip bootstrapping the device-side firmware. To be used for tests with
    // multiple execution phases (due to e.g. manual intervention), to avoid
    // issues from flash being cleared in-between executions.
    #[arg(short, long)]
    skip_bootstrap: bool,

    /// Path to the JSON command files to use for the test. Only the first
    /// file is used.
    #[arg(short, long)]
    command_file: Vec<PathBuf>,

    // Path to create a log CSV file for the Program/Erase test.
    #[arg(short, long)]
    log_file: Option<PathBuf>,

    /// Users should manually provide this arg to acknowledge that they
    /// understand what the test does and wish to run the test.
    #[arg(long)]
    acknowledge_test_action: bool,
}

/// Decode a hex string into a list of bytes.
fn decode_hex_string(string: &str) -> Result<Vec<u8>, ParseIntError> {
    let mut hex_chars = string.trim().trim_start_matches("0x").replace(" ", "");
    if hex_chars.len() % 2 != 0 {
        log::warn!(
            "Input hex string {} contains an odd number of nibbles.",
            string
        );
        hex_chars.push('0');
    }
    (0..hex_chars.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_chars[i..i + 1], 16))
        .collect()
}

// See sw/host/tests/chip/flash_ctrl/endurance_tests/README.md.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub enum FlashTestCommand {
    ProgramErase {
        num_cycles: u32,
        log_granularity: Option<u32>,
        readback_delay_us: Option<u64>,
        allow_ecc_errors: Option<bool>,
        test_data: Option<String>,
        invert_each_cycle: Option<bool>,
    },
    ReadPage {
        expected_data: String,
    },
    WritePage {
        readback_delay_us: Option<u64>,
        data: String,
    },
    TestConfig {
        page_num: Option<u32>,
        high_endurance_en: bool,
        scramble_en: bool,
        ecc_en: bool,
    },
    Wait {
        duration: String,
    },
    ResetTarget {
        repetitions: Option<u32>,
    },
}

impl FlashTestCommand {
    fn execute(
        &self,
        transport: &TransportWrapper,
        uart: &dyn Uart,
        log_file: &mut Option<File>,
    ) -> Result<bool> {
        match self {
            Self::ProgramErase {
                num_cycles,
                log_granularity,
                readback_delay_us,
                allow_ecc_errors,
                test_data,
                invert_each_cycle,
            } => {
                let granularity = log_granularity
                    .map(|x| if x < 1 { 1 } else { x })
                    .unwrap_or(1);
                let decoded_data = match test_data {
                    Some(hex_str) => decode_hex_string(hex_str)?,
                    None => vec![0xA5],
                };
                let test = FlashProgramEraseTest::new(
                    *num_cycles,
                    granularity,
                    readback_delay_us.unwrap_or(0),
                    allow_ecc_errors.unwrap_or(true),
                    &decoded_data,
                    invert_each_cycle.unwrap_or(true),
                );
                test.execute(uart, log_file)
            }
            Self::ReadPage { expected_data } => {
                let decoded_data = decode_hex_string(expected_data)?;
                let read = FlashReadAndCheckPage::new(&decoded_data);
                read.execute(uart)
            }
            Self::WritePage {
                readback_delay_us,
                data,
            } => {
                let decoded_data = decode_hex_string(data)?;
                let write = FlashWritePage::new(readback_delay_us.unwrap_or(0), &decoded_data);
                write.execute(uart)
            }
            Self::TestConfig {
                page_num,
                high_endurance_en,
                scramble_en,
                ecc_en,
            } => {
                let config = FlashTestConfig {
                    page_num: page_num.unwrap_or(u32::MAX),
                    high_endurance_en: *high_endurance_en,
                    scramble_en: *scramble_en,
                    ecc_en: *ecc_en,
                };
                config.write(uart)?;
                Ok(true)
            }
            Self::Wait { duration } => {
                log::info!("Waiting for {}", &duration);
                std::thread::sleep(humantime::parse_duration(duration)?);
                Ok(true)
            }
            Self::ResetTarget { repetitions } => {
                for _ in 0..repetitions.unwrap_or(1) {
                    transport.reset_target(Duration::from_millis(500), true)?;
                    UartConsole::wait_for(
                        &*uart,
                        r"Ready to receive commands",
                        Duration::from_secs(30),
                    )?;
                }
                Ok(true)
            }
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
struct TestCommands {
    page_num: Option<u32>,
    boot_slot: Option<BootSlot>,
    high_endurance_en: bool,
    scramble_en: bool,
    ecc_en: bool,
    commands: Vec<FlashTestCommand>,
}

impl TestCommands {
    fn set_primary_bl0_slot(
        &self,
        transport: &TransportWrapper,
        uart: &dyn Uart,
        rescue: &dyn Rescue,
    ) -> Result<()> {
        let Some(slot) = self.boot_slot else {
            return Ok(());
        };
        rescue.enter(&transport, EntryMode::Reset)?;
        // Set the primary bl0 slot to the specified boot slot, so
        // that the test continues to boot from this slot even after resets.
        rescue.set_next_bl0_slot(slot, slot)?;
        rescue.reboot()?;
        UartConsole::wait_for(
            &*uart,
            r"Ready to receive commands",
            Duration::from_secs(30),
        )?;
        Ok(())
    }

    fn with_config_commands(&self) -> Vec<FlashTestCommand> {
        let init_config_cmd = FlashTestCommand::TestConfig {
            page_num: self.page_num,
            high_endurance_en: self.high_endurance_en,
            scramble_en: self.scramble_en,
            ecc_en: self.ecc_en,
        };
        let mut commands = Vec::from([init_config_cmd.clone()]);
        for command in &self.commands {
            commands.push(command.clone());
            if let FlashTestCommand::ResetTarget { .. } = *command {
                commands.push(init_config_cmd.clone())
            }
        }
        commands
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    opts.init.init_logging();

    // Read & serialize the first specified command file
    let command_file_path = &opts.command_file.first().expect("No command file given");
    let mut command_file = File::open(command_file_path).context("Opening command JSON file")?;
    let mut contents = String::new();
    command_file
        .read_to_string(&mut contents)
        .context("Reading command JSON file")?;
    let test_commands: TestCommands =
        serde_json::from_str(&contents).context("Parsing command JSON contents")?;

    // Verify user acknowledgement. If not given, print out an explanation of
    // the test, and the method for providing acknowledgement.
    if !opts.acknowledge_test_action {
        log::info!(
            "\n\nWARNING: this test intends to wear down physical flash,\n\
            potentially until the point of failure. On silicon, this means\n\
            that the tested pages of flash can no longer be reliably used.\n\
            As the test is command-driven, the scale and distribution of the\n\
            wear will depend on the commands executed, but in the worst case\n\
            this could wear down every accessible flash page in data partion\n\
            0 of both flash banks. For devices other than silicon, you must\n\
            still provide user acknowledgement to run the test, to avoid\n\
            wearing/damaging hardware - it is recommended to keep the number\n\
            of test operations low in such environments.\n\n\
            If you acknowledge that this test will wear down physical flash\n\
            and would like to proceed running the test, add the following\n\
            argument to your Bazel command line invocation:\n\
              --test_arg=--acknowledge-test-action\n"
        );
        return Err(anyhow!("User acknowledgement not provided."));
    }

    // Create a CSV log file if specified
    let mut log_file = match opts.log_file {
        Some(path) => {
            if std::fs::exists(&path)? {
                return Err(anyhow!("Log file already exists, give a different path"));
            }
            let mut file = File::create(path)?;
            FlashProgramEraseTest::log_csv_header(&mut file)?;
            Some(file)
        }
        None => {
            log::info!(
                "You can provide a path to write a log file for this test\n\
                        with `--test_arg=--log-file=\"/path/to/your/log/file.csv\""
            );
            None
        }
    };

    let transport = if !opts.skip_bootstrap {
        opts.init.init_target()?
    } else {
        // Create the transport interface and set up the default pin
        // configurations and UART, but skip bootstrapping.
        let transport = backend::create(&opts.init.backend_opts)?;
        transport.apply_default_configuration(None)?;
        let _uart = opts.init.bootstrap.options.uart_params.create(&transport)?;
        opts.init.load_bitstream.init(&transport)?;
        transport.reset_target(Duration::from_millis(500), true)?;
        transport
    };
    let uart = transport.uart("console")?;
    let rescue = RescueSerial::new(Rc::clone(&uart));
    UartConsole::wait_for(
        &*uart,
        r"Ready to receive commands",
        Duration::from_secs(30),
    )?;
    test_commands.set_primary_bl0_slot(&transport, &*uart, &rescue)?;

    let mut all_succeeded: bool = true;
    for (i, test_cmd) in test_commands.with_config_commands().into_iter().enumerate() {
        let result = test_cmd.execute(&transport, &*uart, &mut log_file)?;
        if !result {
            log::info!("Endurance test step {} failed: {:?}", i, test_cmd);
            all_succeeded = false;
        }
    }
    ensure!(all_succeeded, "One or more test components failed.");
    log::info!("All test components succeeded.");

    Ok(())
}

// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

use crate::io::uart::Uart;
use crate::test_utils::e2e_command::TestCommand;
use crate::test_utils::rpc::{ConsoleRecv, ConsoleSend};
use crate::test_utils::status::Status;

// Bring in the auto-generated sources.
include!(env!("flash"));

fn extend_test_data(data: &[u8]) -> arrayvec::ArrayVec<u32, 512> {
    let mut extended = arrayvec::ArrayVec::<u32, 512>::new();
    const DUMMY_BYTE: [u8; 1] = [0u8; 1];
    let data = if data.is_empty() { &DUMMY_BYTE } else { data };
    let mut data = data.iter().cycle();
    for _ in 0..extended.capacity() {
        let mut next_word = (*data.next().unwrap() as u32) << 24;
        next_word |= (*data.next().unwrap() as u32) << 16;
        next_word |= (*data.next().unwrap() as u32) << 8;
        next_word |= *data.next().unwrap() as u32;
        extended.push(next_word);
    }
    extended
}

impl FlashProgramEraseTest {
    pub fn new(
        num_cycles: u32,
        log_granularity: u32,
        readback_delay_us: u64,
        allow_ecc_errors: bool,
        test_data: &[u8],
        invert_each_cycle: bool,
    ) -> Self {
        Self {
            num_cycles,
            log_granularity,
            readback_delay_us,
            allow_ecc_errors,
            test_data: extend_test_data(test_data),
            invert_each_cycle,
        }
    }

    pub fn log_csv_header(log_file: &mut File) -> Result<()> {
        let headers = vec![
            "cycle",
            "success",
            "ecc_errors",
            "cumulative_erase_micros",
            "cumulative_program_micros",
            "cumulative_read_micros",
        ];
        for (i, header) in headers.iter().enumerate() {
            if i != 0 {
                log_file.write_all(&[b','])?;
            }
            log_file.write_all(&header.to_string().into_bytes())?
        }
        log_file.write_all(&[b'\n'])?;
        log_file.flush()?;
        Ok(())
    }

    pub fn execute(&self, uart: &dyn Uart, log_file: &mut Option<File>) -> Result<bool> {
        TestCommand::FlashProgramEraseTest.send_with_crc(uart)?;
        self.send_with_crc(uart)?;

        // Receive a result every `log_granularity` program/erase cycles.
        let response_timeout = humantime::parse_duration("1y")?;
        for _ in 0..(self.num_cycles.div_ceil(self.log_granularity)) {
            let result = FlashProgramEraseResult::recv(uart, response_timeout, false, false)?;
            if let Some(log) = log_file {
                let values = format!(
                    "{},{},{},{},{},{}\n",
                    result.cycle,
                    result.success,
                    result.ecc_errors,
                    result.erase_us,
                    result.program_us,
                    result.read_us
                );
                log.write_all(&values.bytes().collect::<Vec<_>>())?;
                log.flush()?;
            } else {
                log::info!("Received result: {:?}", result);
            }
            // If the test fails, do not expect to see any more partial results
            if !result.success {
                break;
            }
        }

        // Receive the overall command result
        let status = Status::recv(uart, response_timeout, false, false)?;
        Ok(i32::try_from(status)? > 0)
    }
}

impl FlashReadAndCheckPage {
    pub fn new(expected_data: &[u8]) -> Self {
        Self {
            expected_data: extend_test_data(expected_data),
        }
    }

    pub fn execute(&self, uart: &dyn Uart) -> Result<bool> {
        TestCommand::FlashReadAndCheckPage.send_with_crc(uart)?;
        self.send_with_crc(uart)?;
        let status = Status::recv(uart, Duration::from_secs(30), false, false)?;
        Ok(i32::try_from(status)? > 0)
    }
}

impl FlashWritePage {
    pub fn new(readback_delay_us: u64, data: &[u8]) -> Self {
        Self {
            readback_delay_us,
            data: extend_test_data(data),
        }
    }

    pub fn execute(&self, uart: &dyn Uart) -> Result<bool> {
        TestCommand::FlashWritePage.send_with_crc(uart)?;
        self.send_with_crc(uart)?;
        let status = Status::recv(uart, humantime::parse_duration("1y")?, false, false)?;
        Ok(i32::try_from(status)? > 0)
    }
}

impl FlashTestConfig {
    pub fn write(&self, uart: &dyn Uart) -> Result<()> {
        TestCommand::FlashTestConfig.send_with_crc(uart)?;
        self.send_with_crc(uart)?;
        Status::recv(uart, Duration::from_secs(30), false, false)?;
        Ok(())
    }
}

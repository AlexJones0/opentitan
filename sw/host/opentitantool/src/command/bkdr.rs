// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::any::Any;
use std::convert::From;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use opentitanlib::app::TransportWrapper;
use opentitanlib::app::command::CommandDispatch;
use opentitanlib::io::fpga_bkdr::{BackdoorParams, enter_backdoor_loader};
use opentitanlib::util::vmem::{Section, Vmem, Word};

/// Commands for interacting with the backdoor FPGA loader.
#[derive(Debug, Subcommand, CommandDispatch)]
pub enum InternalBkdrCommand {
    /// Enter the backdoor loader - this *requires* resetting the device.
    Enter(EnterInfo),
    /// Enter "mission mode" - finish & de-assert reset. This is irreversible until the next reset.
    Start(StartInfo),
    /// Display information about the available backdoor targets
    Info(BkdrInfo),
    /// Read words from a target memory via the backdoor.
    Read(ReadInfo),
    /// Write words to a target memory via the backdoor.
    Write(WriteInfo),
    ///// Verify that the contents of some target memory matches some given data.
    //Verify(VerifyInfo),
    // TODO: clear command?
    /// A command that combines entering, writing several files to different targets, and starting.
    Batch(BatchInfo),
    /// Test write-readback command, TO BE REMOVED <-- TODO
    Test(TestInfo),
}

#[derive(Debug, Args)]
pub struct EnterInfo {}

impl CommandDispatch for EnterInfo {
    fn run(
        &self,
        _context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        enter_backdoor_loader(transport)?;

        Ok(None)
    }
}

#[derive(Debug, Args)]
pub struct StartInfo {}

impl CommandDispatch for StartInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(false)?;
        bkdr.set_done()?;

        Ok(None)
    }
}

#[derive(Debug, Args)]
pub struct BkdrInfo {
    /// Optional target to query
    pub target: Option<String>,
}

impl CommandDispatch for BkdrInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(true)?;

        let info: Box<dyn erased_serde::Serialize> = match &self.target {
            Some(id_str) => {
                let target = bkdr
                    .target_by_id_str(id_str)?
                    .context(format!("FPGA target '{id_str}' not found"))?;
                Box::new(target.info)
            }
            None => Box::new(bkdr.targets().to_vec()),
        };

        Ok(Some(info))
    }
}

/// Formats for input/output files used with the backdoor loader
/// TODO: reword above?
/// TODO: mostly support vmem for now?
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum DataFormat {
    Hex,
    Raw,
    Vmem,
}

#[derive(Debug, Args)]
pub struct ReadInfo {
    /// Target to read from.
    pub target: String,

    /// First word address / index to read from.
    pub start: u32,

    /// The number of words to read.
    #[arg(long)]
    pub words: u32,

    /// Optional path to write the output to. If not given, outputs directly to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// The data format to use when outputting words that are read.
    #[arg(long, default_value = "hex")]
    pub format: DataFormat,
}

impl CommandDispatch for ReadInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let _bkdr = context.params.create(transport)?;
        unimplemented!()
    }
}

#[derive(Debug, Args)]
pub struct WriteInfo {
    /// Target to write to.
    pub target: String,

    /// First word address / index to write to.
    #[arg(long)]
    pub offset: Option<u32>,

    /// Read back and verify the written data (may be reasonably longer).
    #[arg(long)]
    pub verify: bool,

    /// The input source to write
    #[command(subcommand)]
    pub input: WriteInput,
}

#[derive(Debug, Subcommand)]
pub enum WriteInput {
    /// Write words given as a whitespace-separated hex string over stdin
    Hex(HexInput),
    /// Write data from a Verilog VMEM file
    Vmem(VmemInput),
    ///// Write data from a raw binary file
    //Bin(BinInput),
}

#[derive(Args, Debug)]
pub struct HexInput {
    /// Input hexadecimal words, with whitespace separating each word
    #[arg(required = true)]
    pub data: String,
}

#[derive(Args, Debug)]
pub struct VmemInput {
    /// Path to the Verilog VMEM file
    pub path: PathBuf,
}

//#[derive(Args, Debug)]
//pub struct BinInput {
//    /// Path to the raw binary file.
//    pub path: PathBuf,
//
//    /// The number of bits in each word.
//    #[arg(long, default_value = 32)]
//    pub word_bits: usize,
//
//    /// Whether words in the binary are tightly packed or not.
//    #[arg(long)]
//    pub packed: bool,
//
//    /// If true, read in little-endian bit order instead.
//    #[arg(long)]
//    pub swap_bits: bool
//}

impl CommandDispatch for WriteInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();

        // Parse the input, which will depend on the given input type.
        let mut sections: Vec<Section> = match &self.input {
            WriteInput::Hex(hex) => {
                let words = hex
                    .data
                    .split_whitespace()
                    .map(|word| {
                        let normalized = if word.len() % 2 != 0 {
                            format!("0{word}")
                        } else {
                            word.to_string()
                        };

                        Ok(Word(hex::decode(&normalized)?))
                    })
                    .collect::<Result<Vec<_>>>()?;

                vec![Section {
                    addr: 0,
                    data: words,
                }]
            }
            WriteInput::Vmem(vmem) => {
                log::info!("Loading VMEM file: {}", vmem.path.display());
                let vmem_content = fs::read_to_string(&vmem.path)?;
                //println!("{}", vmem_content);
                let mut vmem = Vmem::from_str(&vmem_content, None)?;
                //println!("{:?}", vmem);
                vmem.merge_sections(None); // TODO: keep or remove? Need to test either way
                vmem.sections().cloned().collect()
            } //WriteInput::Bin(bin_path) => {},
        };

        // If an offset is given, all sections must be offset by that amount.
        if let Some(offset) = self.offset {
            for section in &mut sections {
                section.addr += offset;
            }
        }

        // Connect to the backdoor and try and find the requested target.
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(true)?;
        let mut target = bkdr
            .target_by_id_str(&self.target)?
            .context(format!("FPGA target '{}' not found", self.target))?;

        // Perform the write(s)
        log::info!("Writing to the {}...", self.target);
        for section in sections {
            log::debug!(
                "Writing section of size {} to word {} of target {}",
                section.data.len(),
                section.addr,
                self.target
            );
            target.write(section.addr, &section.data, false, false)?;
            if self.verify {
                let readback = target.read(section.addr, section.data.len() as u32, false)?;
                for (write_word, read_word) in readback.into_iter().zip(section.data) {
                    let write_word = write_word
                        .0
                        .iter()
                        .skip_while(|&x| *x == 0)
                        .collect::<Vec<_>>();
                    let read_word = read_word
                        .0
                        .iter()
                        .skip_while(|&x| *x == 0)
                        .collect::<Vec<_>>();
                    if write_word != read_word {
                        bail!(
                            "Readback of written data failed. Expected: {:?}, Got: {:?}",
                            write_word,
                            read_word
                        );
                    }
                }
            }
        }
        log::info!("self.verify={}", self.verify);

        Ok(None)
    }
}

//#[derive(Debug, Args)]
//pub struct VerifyInfo {
//    /// Target to read from.
//    pub target: String,
//
//    /// First word address / index to read from.
//    #[arg(long)]
//    pub offset: Option<u32>,
//
//    /// Verify data loaded from a given file.
//    #[arg(long, conflicts_with = "data")]
//    pub file: Option<PathBuf>,
//
//    /// The data format of the input if using `--file`.
//    #[arg(long)]
//    pub format: Option<DataFormat>,
//}
//
//impl CommandDispatch for VerifyInfo {
//    fn run(
//        &self,
//        context: &dyn Any,
//        transport: &TransportWrapper,
//    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
//        let context = context.downcast_ref::<BkdrCommand>().unwrap();
//        let _bkdr = context.params.create(transport)?;
//        unimplemented!()
//    }
//}

#[allow(dead_code)] // TODO
#[derive(Debug, Clone)]
pub struct TargetWrite {
    pub target: String,
    pub path: PathBuf,
}

impl FromStr for TargetWrite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (target, path) = s
            .split_once('=')
            .context("expected target=file, got {s:?}")?;
        if target.is_empty() {
            bail!("target name cannot be empty");
        }
        if path.is_empty() {
            bail!("file path cannot be empty");
        }

        Ok(TargetWrite {
            target: target.to_string(),
            path: PathBuf::from(path),
        })
    }
}

#[derive(Debug, Args)]
pub struct BatchInfo {
    /// Mappings between targets & files to write to them (at offset 0).
    #[arg(long = "target", required = true, value_name = "TARGET=FILE")]
    pub targets: Vec<TargetWrite>,

    // Override format for all targets (if omitted, these will be inferred from extensions)
    #[arg(long)]
    pub format: Option<DataFormat>,
}

impl CommandDispatch for BatchInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let _bkdr = context.params.create(transport)?;
        unimplemented!()
    }
}

/// TODO: this is all meaningless implementation just for testing, to be removed.
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
        let mut bkdr = bkdr.connect(true)?;
        let mut rom_bkdr = bkdr
            .target_by_id_str("ROM")?
            .context("Could not find ROM target for testing")?;
        println!("{:?}", rom_bkdr.read(0x0, 10, true)?);
        rom_bkdr.write(0x0, &[Word(vec![0u8])], false, true)?;
        println!("{:?}", rom_bkdr.read(0x0, 1, true)?);
        let words = (1u8..5u8).map(|v| Word(vec![v])).collect::<Vec<_>>();
        rom_bkdr.write(0x0, &words, true, true)?;
        println!("{:?}", rom_bkdr.read(0x2, 4, true)?);
        let mut aon_bkdr = bkdr
            .target_by_id_str("AON")?
            .context("Could not find AON target for testing")?;
        let words = [11, 22, 33, 44, 55, 66, 77, 88u8]
            .into_iter()
            .map(|v| Word(vec![v, v + 1, v + 2, v + 4]))
            .collect::<Vec<_>>();
        aon_bkdr.write(0x203, &words, false, false)?;
        println!("{:?}", aon_bkdr.read(0x200, 16, false)?);
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

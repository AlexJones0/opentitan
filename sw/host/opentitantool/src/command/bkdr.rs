// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::any::Any;
use std::convert::From;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use opentitanlib::app::TransportWrapper;
use opentitanlib::app::command::CommandDispatch;
use opentitanlib::io::fpga_bkdr::{
    Backdoor, BackdoorParams, enter_backdoor_loader, load_raw_words, load_vmem_words,
};
use opentitanlib::util::vmem::{Section, Word};

// TODO: need to move most of this out of this file and into OTLib.
// All the functionality should live there, this should just be lean
// wrappers for the most part.

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
    /// Verify that the contents of some target memory matches some given data.
    Verify(VerifyInfo),
    /// A command that combines entering, writing several files to different targets, and starting.
    Batch(BatchInfo),
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

        // Connect to the backdoor and try and find the requested target.
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(true)?;
        let mut target = bkdr
            .target_by_id_str(&self.target)?
            .context(format!("FPGA target '{}' not found", self.target))?;

        // Perform the read
        log::debug!(
            "Reading {} words at offset {} from target {}...",
            self.words,
            self.start,
            self.target
        );
        let words = target.read(self.start, self.words, true)?;

        let mut out: Box<dyn Write> = if let Some(out_path) = &self.output {
            Box::new(std::fs::File::create(out_path)?)
        } else {
            Box::new(std::io::stdout())
        };

        // TODO: untested, check and fix
        match self.format {
            DataFormat::Hex => {
                write!(
                    out,
                    "{}",
                    words
                        .into_iter()
                        .map(|w| hex::encode(w.0))
                        .collect::<Vec<_>>()
                        .join(" ")
                )?;
            }
            DataFormat::Raw => {
                for word in words {
                    out.write_all(&word.0)?;
                }
            }
            DataFormat::Vmem => {
                let num_words = words.len();
                let addr_width = (num_words - 1).to_string().len();

                let num_bytes = target.info.width.div_ceil(8);
                let word_width = (num_bytes * 2) as usize;

                write!(
                    out,
                    "// {} memory file with {} x {} bit layout ({} x {} bytes)",
                    target.info.id_str(),
                    target.info.width,
                    target.info.depth,
                    num_bytes,
                    target.info.depth
                )?;
                // TODO: this might actually already be the correct number of bytes.
                // Double check if hex::encode respects that in the output or not,
                // and remove the additional width bounding logic if so.
                write!(
                    out,
                    "{}",
                    words
                        .into_iter()
                        .enumerate()
                        .map(|(index, word)| {
                            format!(
                                "@{:0addr_width$} {:0>word_width$}",
                                index,
                                hex::encode(word.0)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                )?;
            }
        }

        Ok(None)
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
    /// Input words given as a whitespace-separated hex string over stdin
    Hex(HexInput),
    /// Input data from a Verilog VMEM file
    Vmem(VmemInput),
    /// Input data from a raw binary file
    Raw(RawInput),
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

#[derive(Args, Debug)]
pub struct RawInput {
    /// Path to the raw binary file.
    pub path: PathBuf,

    /// The number of bits in each word.
    #[arg(long, default_value_t = 32)]
    pub bits_per_word: usize,

    /// Whether words in the binary are tightly packed or not (i.e. byte-aligned).
    #[arg(long)]
    pub packed: bool,

    /// If true, interpret bits in an MSB-first order.
    #[arg(long)]
    pub swap_bits: bool,

    /// If true, interpret bytes of words in a big-endian order.
    #[arg(long)]
    pub swap_bytes: bool,
}

impl WriteInput {
    fn load_input(input: &WriteInput, offset: Option<u32>) -> Result<Vec<Section>> {
        let mut sections: Vec<Section> = match input {
            WriteInput::Hex(hex) => WriteInput::load_hex_words(hex)?,
            WriteInput::Vmem(vmem) => {
                log::info!("Loading VMEM file: {}", vmem.path.display());
                let vmem_content = fs::read_to_string(&vmem.path)?;
                load_vmem_words(&vmem_content)?
            }
            WriteInput::Raw(bin) => {
                log::info!("Loading raw binary: {}", bin.path.display());
                let bytes = fs::read(&bin.path)?;
                let data = load_raw_words(
                    &bytes,
                    bin.bits_per_word,
                    bin.packed,
                    bin.swap_bits,
                    bin.swap_bytes,
                );
                vec![Section { addr: 0, data }]
            }
        };

        // If an offset is given, all sections must be offset by that amount.
        if let Some(offset) = offset {
            for section in &mut sections {
                section.addr += offset;
            }
        }

        Ok(sections)
    }

    fn load_hex_words(hex: &HexInput) -> Result<Vec<Section>> {
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

        Ok(vec![Section {
            addr: 0,
            data: words,
        }])
    }
}

// TODO: where should these live? Probably not here.
fn left_trim_zeroes(word: &mut Word) {
    match word.0.iter().position(|&x| x != 0) {
        Some(i) => {
            word.0.drain(0..i);
        }
        None => {
            word.0.clear();
        }
    };
}

fn verify_readback(input: &mut [Word], readback: &mut [Word], mut offset: u32) -> Result<()> {
    for (write_word, read_word) in readback.iter_mut().zip(input) {
        left_trim_zeroes(write_word);
        left_trim_zeroes(read_word);

        if write_word != read_word {
            bail!(
                "Read verification at word {} failed. Expected: {:?}, Got: {:?}",
                offset,
                write_word,
                read_word
            );
        }

        offset += 1;
    }

    Ok(())
}

fn write_to_target(
    bkdr: &mut Backdoor,
    target_id: &str,
    input: &WriteInput,
    offset: Option<u32>,
    verify: bool,
) -> Result<()> {
    // Parse the input, which will depend on the given input type.
    let sections: Vec<Section> = WriteInput::load_input(input, offset)?;

    // Try and find the requested target.
    let mut target = bkdr
        .target_by_id_str(target_id)?
        .context(format!("FPGA target '{}' not found", target_id))?;

    // Perform the write(s)
    log::info!("Writing to the {}...", target_id);
    for mut section in sections {
        log::debug!(
            "Writing section of size {} to word {} of target {}",
            section.data.len(),
            section.addr,
            target_id
        );
        target.write(section.addr, &section.data, false, verify)?;

        // Readback and verify if requested
        if verify {
            let mut readback = target.read(section.addr, section.data.len() as u32, false)?;
            verify_readback(&mut section.data, &mut readback, section.addr)?;
        }
    }

    Ok(())
}

impl CommandDispatch for WriteInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(true)?;
        write_to_target(
            &mut bkdr,
            &self.target,
            &self.input,
            self.offset,
            self.verify,
        )?;

        Ok(None)
    }
}

// TODO: can I flatten `VerifyInfo` into `WriteInfo` and reduce a lot of duplication?
// In both the parameter definitions and the implementation.
#[derive(Debug, Args)]
pub struct VerifyInfo {
    /// Target to verify the contents of.
    pub target: String,

    /// First word address / index to read from.
    #[arg(long)]
    pub offset: Option<u32>,

    /// The input source to verify against.
    #[command(subcommand)]
    pub input: WriteInput,
}

impl CommandDispatch for VerifyInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();

        // Parse the input, which will depend on the given input type.
        let sections: Vec<Section> = WriteInput::load_input(&self.input, self.offset)?;

        // Connect to the backdoor and try and find the requested target.
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(true)?;
        let mut target = bkdr
            .target_by_id_str(&self.target)?
            .context(format!("FPGA target '{}' not found", self.target))?;

        // Read the data and check it matches our input.
        for mut section in sections {
            log::debug!(
                "Verifying section of size {} to word {} of target {}",
                section.data.len(),
                section.addr,
                self.target
            );
            let mut readback = target.read(section.addr, section.data.len() as u32, false)?;
            verify_readback(&mut section.data, &mut readback, section.addr)?;
        }

        Ok(None)
    }
}

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

    /// After finishing programming, enter "mission mode" & start the chip.
    #[arg(long)]
    pub start: bool,

    /// Read back and verify the written data (may be reasonably longer).
    #[arg(long)]
    pub verify: bool,
}

impl CommandDispatch for BatchInfo {
    fn run(
        &self,
        context: &dyn Any,
        transport: &TransportWrapper,
    ) -> Result<Option<Box<dyn erased_serde::Serialize>>> {
        let context = context.downcast_ref::<BkdrCommand>().unwrap();
        let bkdr = context.params.create(transport)?;
        let mut bkdr = bkdr.connect(true)?;

        for write_op in &self.targets {
            // TODO: currently assumes all inputs are VMems, maybe extend `TargetWrite`
            // and/or make use of the file extension. Alo assumes offsets of 0 always.
            let input = WriteInput::Vmem(VmemInput {
                path: write_op.path.clone(),
            });
            write_to_target(&mut bkdr, &write_op.target, &input, Some(0), self.verify)?;
        }

        if self.start {
            bkdr.set_done()?;
        }

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

// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This module contains code for working with Verilog `vmem` files.
//!
//! This includes the [`Vmem'] representation which can be parsed from a string.

use std::iter;

mod parser;

use parser::VmemParser;
pub use parser::{ParseError, ParseResult};

/// Representation of a vmem file.
///
/// These files consist of sections which are runs of memory starting at some address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmem {
    sections: Vec<Section>,
}

/// Section of memory at some address in the vmem file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Section {
    pub addr: u32,
    pub data: Vec<Word>,
}

/// A singular word to assign to some element of memory - the width/size of a word depends on
/// what the VMEM is being read into.
/// TODO: maybe should be a Box<u8> instead?
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Word(pub Vec<u8>);

impl Vmem {
    /// Parse a complete VMEM file from a string.
    ///
    /// If word_bytes = Some(n) is given, then the VMEM is interpreted such that each
    /// word is `n` bytes, and the stride is 1 byte per address. The SREC Verilog VMEM format
    /// operates on units of bytes, so word sizes that are not byte-divisible will be zero-
    /// extended (in the MSBs).
    ///
    /// If word_bytes = None is given, then the VMEM is interpreted such that the stride
    /// is 1 word per address.
    pub fn from_str(s: &str, word_bytes: Option<usize>) -> Result<Self, ParseError> {
        VmemParser::parse(s, word_bytes)
    }
}

impl Vmem {
    /// Returns an iterator over sections of the vmem file.
    pub fn sections(&self) -> impl Iterator<Item = &Section> {
        // Filter out empty sections.
        self.sections
            .iter()
            .filter(|section| !section.data.is_empty())
    }
}

/// Represents some value at some address as specified in the vmem file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    pub addr: u32,
    pub value: Word,
}

impl Vmem {
    /// Returns an iterator over all data of the VMEM file.
    /// The word size (in bytes, ceiling for non-byte-divisible sizes) must be given to
    /// be able to interpret the stride of memory element addresses in the VMEM.
    pub fn data_addrs(&self, word_bytes: usize) -> impl Iterator<Item = Data> + '_ {
        self.sections()
            .flat_map(move |section| section.data_addrs(word_bytes))
    }

    /// Merge any contiguous sections in the VMEM together.
    ///
    /// If word_bytes = Some(n) is given, then the VMEM is interpreted such that each
    /// word is `n` bytes, and the stride is 1 byte per address. The SREC Verilog VMEM format
    /// operates on units of bytes, so word sizes that are not byte-divisible will be zero-
    /// extended (in the MSBs).
    ///
    /// If word_bytes = None is given, then the VMEM is interpreted such that the stride
    /// is 1 word per address.
    pub fn merge_sections(&mut self, word_bytes: Option<usize>) {
        let mut res: Vec<Section> = Vec::new();
        // we modify in place as much as possible to avoid copying data uselessly
        for mut sec in std::mem::take(&mut self.sections) {
            match res.last_mut() {
                Some(ref mut last) => {
                    let nwords = last.data.len() as u32;
                    let size = nwords * word_bytes.unwrap_or(1) as u32;
                    if last.addr + size == sec.addr {
                        last.data.append(&mut sec.data)
                    } else {
                        res.push(sec)
                    }
                }
                _ => res.push(sec),
            }
        }
        self.sections = res
    }
}

impl Section {
    /// Returns an iterator over all data of this section of the VMEM file.
    /// The word size (in bytes, ceiling for non-byte-divisible sizes) must be given to
    /// be able to interpret the stride of memory element addresses in the VMEM.
    pub fn data_addrs(&self, word_bytes: usize) -> impl Iterator<Item = Data> + '_ {
        let addrs = (self.addr..).step_by(word_bytes);
        let values = self.data.iter();
        iter::zip(addrs, values).map(|(addr, value)| Data {
            addr,
            value: value.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vmem_data() {
        let vmem = Vmem::from_str("@10 12 23 34 @20 @26 45", Some(4)).unwrap();
        let expected =
            [(0x40, 0x12), (0x44, 0x23), (0x48, 0x34), (0x98, 0x45)].map(|(addr, value)| Data {
                addr,
                value: Word(vec![value]),
            });

        let data: Vec<_> = vmem.data_addrs(4).collect();
        assert_eq!(data, expected);
    }

    #[test]
    fn section_data() {
        let section = Section {
            addr: 0x42,
            data: vec![
                Word(vec![0x12]),
                Word(vec![0x23]),
                Word(vec![0x34]),
                Word(vec![0x45]),
            ],
        };
        let expected =
            [(0x42, 0x12), (0x46, 0x23), (0x4a, 0x34), (0x4e, 0x45)].map(|(addr, value)| Data {
                addr,
                value: Word(vec![value]),
            });

        let data: Vec<_> = section.data_addrs(4).collect();
        assert_eq!(data, expected);
    }

    // TODO: add new tests for word_bytes functionality. Completely untested for now.
}

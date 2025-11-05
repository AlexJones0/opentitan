// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub fn to_hex_bytes(s: &[u8]) -> std::io::Result<Vec<u8>> {
    let (chunks, []) = s.as_chunks::<2>() else {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };
    let from_ascii_hex = |c| match c {
        0x30..=0x39 => Ok(c - 0x30),
        0x41..=0x46 => Ok(c - 0x41 + 10),
        0x61..=0x66 => Ok(c - 0x61 + 10),
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    };
    chunks
        .iter()
        .try_fold(Vec::with_capacity(chunks.len()), |mut acc, chunk| {
            acc.push(from_ascii_hex(chunk[0])? << 4 | from_ascii_hex(chunk[1])?);
            Ok::<Vec<u8>, std::io::Error>(acc)
        })
}

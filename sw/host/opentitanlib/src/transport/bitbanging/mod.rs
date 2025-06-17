// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod uart;

use std::collections::HashMap;
use std::rc::{Rc, Weak};

use anyhow::Result;

use crate::io::uart::Uart;
use crate::transport::{GpioPin, Transport};

pub struct BitbangWrapperBuilder {
    // We cache the implementations of our bitbanging interfaces, as often the
    // same peripheral/IO is opened multiple times without dropping the previous
    // one, and we need to ensure the interfaces have consistent properties and
    // do not repeat e.g. muxing and pin monitoring logic.
    uarts: HashMap<String, Weak<dyn Uart>>,
}

impl Default for BitbangWrapperBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BitbangWrapperBuilder {
    pub fn new() -> Self {
        Self {
            uarts: HashMap::new(),
        }
    }

    pub fn uart(
        &mut self,
        name: &str,
        rx: Rc<dyn GpioPin>,
        tx: Rc<dyn GpioPin>,
        transport: Rc<dyn Transport>,
    ) -> Result<Rc<dyn Uart>> {
        // If a BitbangWrapperUart already exists for this specific UART
        // instance and it is still in use, return a reference to it.
        if let Some(instance) = self.uarts.get(name) {
            if let Some(bitbang_uart) = instance.upgrade() {
                return Ok(bitbang_uart);
            }
        }

        // Otherwise, construct a new BitbangWrapperUart
        let uart = transport.uart(name)?;
        let bitbang_uart: Rc<dyn Uart> =
            Rc::new(uart::BitbangWrapperUart::new(uart, rx, tx, transport)?);
        self.uarts
            .insert(name.to_string(), Rc::downgrade(&bitbang_uart));

        Ok(bitbang_uart)
    }
}

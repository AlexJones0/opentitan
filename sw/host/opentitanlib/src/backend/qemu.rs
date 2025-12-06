// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::transport::Transport;
use crate::transport::qemu::Qemu;

#[derive(Clone, Debug, Args)]
pub struct QemuOpts {
    /// Path to the TTY connected to the QEMU monitor.
    ///
    /// Must be configured in `control`/QMP mode (the JSON protocol).
    #[arg(long, required_if_eq("interface", "qemu"))]
    pub qemu_monitor_tty: Option<PathBuf>,

    // TODO document / rework socket connections
    #[arg(long)]
    pub qemu_gpio_sock: Option<PathBuf>,

    /// Path to the socket connected to the RV_DM JTAG TAP Ctrl.
    /// Allows OpenOCD to communicate via the Remote-Bitbang protocol.
    ///
    /// By default this is retrieved from the monitor, but if QEMU was
    /// given an absolute path and the working directory has changed
    /// then this will be wrong, so this option provides an override
    #[arg(long)]
    pub qemu_rv_dm_jtag_sock: Option<PathBuf>,

    /// Path to the socket connected to the LC_CTRL JTAG TAP Ctrl.
    /// Allows OpenOCD to communicate via the Remote-Bitbang protocol.
    ///
    /// By default this is retrieved from the monitor, but if QEMU was
    /// given an absolute path and the working directory has changed
    /// then this will be wrong, so this option provides an override
    #[arg(long)]
    pub qemu_lc_ctrl_jtag_sock: Option<PathBuf>,

    /// Quit QEMU when finished.
    #[arg(long, default_value_t = false)]
    pub qemu_quit: bool,
}

pub fn create(args: &QemuOpts) -> Result<Box<dyn Transport>> {
    Ok(Box::new(Qemu::from_options(args.clone())?))
}

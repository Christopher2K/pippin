// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 macshare contributors. Protocol knowledge derived from
// iShareScreen (https://github.com/renegadelink/iShareScreen), AGPL-3.0-or-later.

//! macshare: a native client for macOS Screen Sharing's high-performance
//! (HEVC) mode.

mod clipboard;
#[cfg(test)]
mod interop_tests;
mod proto;
mod rtp;
mod session;
mod ui;
mod video;

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result, bail};
use clap::Parser;

use proto::handshake::SessionMode;

#[derive(Parser)]
#[command(version, about = "Connect to a Mac's built-in Screen Sharing in high-performance mode")]
struct Cli {
    /// Host name or IPv4 address of the Mac.
    host: String,
    /// macOS account name.
    #[arg(short, long, env = "MACSHARE_USER")]
    user: String,
    /// Account password. Prompted for if not set.
    #[arg(long, env = "MACSHARE_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    #[arg(long, default_value_t = 5900)]
    port: u16,
    /// Share the console user's screen, or open a separate login session.
    #[arg(long, value_enum, default_value_t = SessionMode::Share)]
    session: SessionMode,
    /// Initial window size in logical pixels, e.g. 1600x900.
    #[arg(long, value_parser = parse_size, default_value = "1600x900")]
    size: (u32, u32),
    /// Backing scale for the virtual display (1 = flat, 2 = Retina).
    /// Defaults to 2 on HiDPI screens, else 1.
    #[arg(long)]
    scale: Option<f64>,
    /// Keep the remote resolution fixed instead of following the window.
    #[arg(long)]
    no_auto_resize: bool,
    /// Send Ctrl as Command and Super as Control.
    #[arg(long)]
    swap_ctrl_cmd: bool,
    /// Decode on the CPU even if CUDA is available.
    #[arg(long)]
    no_hw: bool,
    /// Software decode threads. Pictures are split by CTU row (wavefront),
    /// so more threads add no latency; gains level off around 4-5.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..=16))]
    decode_threads: u32,
    /// Skip the preliminary connection that wakes the host's daemon.
    #[arg(long)]
    no_warmup: bool,
    /// More logging; repeat for debug output.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn parse_size(s: &str) -> Result<(u32, u32), String> {
    let (w, h) = s.split_once(['x', 'X']).ok_or("expected WIDTHxHEIGHT")?;
    let w = w.trim().parse().map_err(|_| "bad width")?;
    let h = h.trim().parse().map_err(|_| "bad height")?;
    if w < 320 || h < 200 {
        return Err("size too small".into());
    }
    Ok((w, h))
}

fn resolve_ipv4(host: &str, port: u16) -> Result<Ipv4Addr> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .with_context(|| format!("{host} has no IPv4 address"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let default_filter = match cli.verbose {
        0 => "macshare=info,wgpu=error,naga=error",
        1 => "macshare=debug,wgpu=warn",
        _ => "macshare=trace,wgpu=info",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .with_target(false)
        .init();
    video::decoder::set_log_level(cli.verbose > 0);

    if let Some(s) = cli.scale
        && !(1.0..=3.0).contains(&s) {
            bail!("--scale must be between 1 and 3");
        }
    let host = resolve_ipv4(&cli.host, cli.port)?;
    let password = match cli.password {
        Some(p) => p,
        None => rpassword::prompt_password(format!("Password for {}@{}: ", cli.user, cli.host))?,
    };
    let cfg = session::Config {
        host,
        port: cli.port,
        user: cli.user,
        password,
        session_mode: cli.session,
        hardware_decode: !cli.no_hw,
        decode_threads: cli.decode_threads,
        warmup: !cli.no_warmup,
    };
    let opts = ui::Options {
        title: format!("{} — macshare", cli.host),
        size: cli.size,
        scale: cli.scale,
        auto_resize: !cli.no_auto_resize,
        swap_ctrl_cmd: cli.swap_ctrl_cmd,
    };
    ui::run(cfg, opts)
}

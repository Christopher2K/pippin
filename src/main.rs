// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 macshare contributors. Protocol knowledge derived from
// iShareScreen (https://github.com/renegadelink/iShareScreen), AGPL-3.0-or-later.

//! macshare: a native client for macOS Screen Sharing's high-performance
//! (HEVC) mode.

mod clipboard;
mod credentials;
#[cfg(test)]
mod interop_tests;
mod proto;
mod rtp;
mod session;
mod ui;
mod video;

use std::io::{BufRead, IsTerminal};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

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
    /// Account password. Otherwise taken from the keyring or prompted for.
    #[arg(long, env = "MACSHARE_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Read the password from the first line of stdin.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
    /// Save the password to the keyring once it authenticates, without
    /// asking. Otherwise only a prompted password is offered for saving.
    #[arg(long)]
    save_password: bool,
    /// Delete the keyring entry for this account and exit.
    #[arg(long)]
    forget_password: bool,
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
    let account = credentials::account(&cli.user, &cli.host, cli.port);
    let store: Arc<dyn credentials::Store> = Arc::new(credentials::Keyring);
    if cli.forget_password {
        match store.delete(&account) {
            Ok(true) => println!("removed stored password for {account}"),
            Ok(false) => println!("no stored password for {account}"),
            Err(e) => tracing::warn!("keyring unavailable: {e:#}"),
        }
        return Ok(());
    }
    let host = resolve_ipv4(&cli.host, cli.port)?;
    let mut stdin = cli.password_stdin.then(|| std::io::stdin().lock());
    let (password, source) = credentials::resolve(
        cli.password,
        stdin.as_mut().map(|s| s as &mut dyn BufRead),
        store.as_ref(),
        &account,
        || Ok(rpassword::prompt_password(format!("Password for {}@{}: ", cli.user, cli.host))?),
    )?;
    drop(stdin);
    let on_auth: session::AuthHook = {
        let (save, password) = (cli.save_password, password.clone());
        let interactive = std::io::stdin().is_terminal();
        Arc::new(move |ok| {
            // Runs on the control thread; asking must not hold up the session.
            let asks = ok && !save && credentials::should_save(source, save, interactive);
            let (store, account, password) = (store.clone(), account.clone(), password.clone());
            let finish = move || {
                credentials::after_auth(store.as_ref(), &account, &password, source, ok, save, || {
                    interactive && credentials::confirm_save(&mut std::io::stdin().lock())
                })
            };
            if asks {
                std::thread::spawn(finish);
            } else {
                finish();
            }
        })
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
        on_auth: Some(on_auth),
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

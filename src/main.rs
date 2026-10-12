// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 macshare contributors. Protocol knowledge derived from
// iShareScreen (https://github.com/renegadelink/iShareScreen), AGPL-3.0-or-later.

//! macshare: a native client for macOS Screen Sharing's high-performance
//! (HEVC) mode.

mod clipboard;
mod credentials;
mod errors;
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
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use clap::Parser;

use proto::handshake::SessionMode;

#[derive(Parser)]
#[command(version, about = "Connect to a Mac's built-in Screen Sharing in high-performance mode")]
struct Cli {
    /// Host name or IPv4 address of the Mac. Asked for in the connect
    /// dialog when missing and there is no terminal.
    host: Option<String>,
    /// macOS account name.
    #[arg(short, long, env = "MACSHARE_USER")]
    user: Option<String>,
    /// Always show the connect dialog, even with a terminal or a stored
    /// password. It's shown anyway when something is missing and stdin
    /// isn't a terminal (e.g. launched from a .desktop file).
    #[arg(long)]
    dialog: bool,
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
    /// Exit when the connection drops instead of reconnecting.
    #[arg(long)]
    no_reconnect: bool,
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

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Session failures arrive already classified; full chains for
            // everything are at debug level.
            tracing::debug!("{e:?}");
            eprintln!("macshare: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
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
    let store: Arc<dyn credentials::Store> = Arc::new(credentials::Keyring);
    if cli.forget_password {
        let (Some(host), Some(user)) = (&cli.host, &cli.user) else {
            bail!("--forget-password needs the host and --user");
        };
        let account = credentials::account(user, host, cli.port);
        match store.delete(&account) {
            Ok(true) => println!("removed stored password for {account}"),
            Ok(false) => println!("no stored password for {account}"),
            Err(e) => tracing::warn!("keyring unavailable: {e:#}"),
        }
        return Ok(());
    }
    let tty = std::io::stdin().is_terminal();
    let target = cli.host.clone().zip(cli.user.clone());
    let mut found = None;
    if let Some((host, user)) = &target
        && !cli.dialog
    {
        let mut stdin = cli.password_stdin.then(|| std::io::stdin().lock());
        let account = credentials::account(user, host, cli.port);
        found = credentials::lookup(
            cli.password.clone(),
            stdin.as_mut().map(|s| s as &mut dyn BufRead),
            store.as_ref(),
            &account,
        )?;
    }
    let mut event_loop = ui::event_loop()?;
    let mode = credentials::choose(cli.dialog, target.is_some(), found.is_some(), tty);
    let (host, user, password, source) = match (mode, target, found) {
        (credentials::Mode::Direct, Some((h, u)), Some((p, s))) => (h, u, p, s),
        (credentials::Mode::Terminal, Some((h, u)), _) => {
            let p = rpassword::prompt_password(format!("Password for {u}@{h}: "))?;
            (h, u, p, credentials::Source::Prompt)
        }
        (credentials::Mode::Dialog, ..) => return dialog_loop(&mut event_loop, &cli, &store),
        _ => bail!("the host and --user are required (or use --dialog)"),
    };
    connect(&mut event_loop, &cli, &store, &host, &user, password, source, cli.save_password, tty).map(drop)
}

/// Shows the connect dialog until a session runs or the user cancels; a
/// rejected password brings the dialog back with an error line.
fn dialog_loop(
    event_loop: &mut winit::event_loop::EventLoop<ui::Tagged>,
    cli: &Cli,
    store: &Arc<dyn credentials::Store>,
) -> Result<()> {
    let mut fields = ui::dialog::Fields {
        host: cli.host.clone().unwrap_or_default(),
        user: cli.user.clone().unwrap_or_default(),
        password: cli.password.clone().unwrap_or_default(),
        save: cli.save_password,
    };
    let mut error = None;
    loop {
        let Some(f) = ui::dialog::run(event_loop, fields.clone(), error.take())? else {
            return Ok(());
        };
        let source = credentials::Source::Dialog;
        match connect(event_loop, cli, store, &f.host, &f.user, f.password.clone(), source, f.save, false)? {
            Outcome::Done => return Ok(()),
            Outcome::Retry(msg) => {
                error = Some(msg);
                fields = ui::dialog::Fields { password: String::new(), ..f };
            }
        }
    }
}

enum Outcome {
    Done,
    /// The details didn't work; ask again with this message.
    Retry(String),
}

/// Runs one session. For a dialog password, auth rejection and an
/// unresolvable host come back as `Retry` so the dialog can ask again.
#[allow(clippy::too_many_arguments)]
fn connect(
    event_loop: &mut winit::event_loop::EventLoop<ui::Tagged>,
    cli: &Cli,
    store: &Arc<dyn credentials::Store>,
    host_name: &str,
    user: &str,
    password: String,
    source: credentials::Source,
    save: bool,
    interactive: bool,
) -> Result<Outcome> {
    let from_dialog = source == credentials::Source::Dialog;
    let host = match resolve_ipv4(host_name, cli.port) {
        Ok(h) => h,
        Err(e) if from_dialog => return Ok(Outcome::Retry(format!("{e:#}"))),
        Err(e) => return Err(e),
    };
    let account = credentials::account(user, host_name, cli.port);
    let rejected = Arc::new(AtomicBool::new(false));
    // The hook runs for every reconnect too; save (or ask) only for the
    // first success. One connect() call is one password, so a new password
    // typed into the dialog after a rejection gets its own chance.
    let save_handled = Arc::new(AtomicBool::new(false));
    let on_auth: session::AuthHook = {
        let (store, password, rejected) = (store.clone(), password.clone(), rejected.clone());
        Arc::new(move |ok| {
            rejected.store(!ok, Ordering::SeqCst);
            if ok && save_handled.swap(true, Ordering::SeqCst) {
                return;
            }
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
        user: user.to_owned(),
        password,
        session_mode: cli.session,
        hardware_decode: !cli.no_hw,
        decode_threads: cli.decode_threads,
        warmup: !cli.no_warmup,
        on_auth: Some(on_auth),
        resumed: false,
    };
    let opts = ui::Options {
        title: format!("{host_name} — macshare"),
        size: cli.size,
        scale: cli.scale,
        auto_resize: !cli.no_auto_resize,
        swap_ctrl_cmd: cli.swap_ctrl_cmd,
        reconnect: !cli.no_reconnect,
    };
    let result = ui::run(event_loop, cfg, opts);
    if result.is_err() && from_dialog && rejected.load(Ordering::SeqCst) {
        return Ok(Outcome::Retry("Wrong user name or password".into()));
    }
    result.map(|()| Outcome::Done)
}

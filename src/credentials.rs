// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 macshare contributors.

//! Password resolution and storage in the desktop keyring (Secret Service).
//! Keyring trouble is only ever a warning; the prompt is always the fallback.

use std::io::BufRead;

use anyhow::{Context, Result, bail};

const SERVICE: &str = "macshare";

/// Where the password came from, which decides what happens after auth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--password` or `MACSHARE_PASSWORD`.
    Explicit,
    Stdin,
    Keyring,
    Prompt,
}

/// A password store keyed by account, `user@host:port`.
pub trait Store: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<String>>;
    fn set(&self, account: &str, password: &str) -> Result<()>;
    /// Returns whether an entry existed.
    fn delete(&self, account: &str) -> Result<bool>;
}

/// The system keyring via the `keyring` crate.
pub struct Keyring;

impl Keyring {
    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, account).context("opening keyring entry")
    }
}

impl Store for Keyring {
    fn get(&self, account: &str) -> Result<Option<String>> {
        match Self::entry(account)?.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context("reading keyring"),
        }
    }

    fn set(&self, account: &str, password: &str) -> Result<()> {
        Self::entry(account)?.set_password(password).context("writing keyring")
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(e).context("deleting keyring entry"),
        }
    }
}

pub fn account(user: &str, host: &str, port: u16) -> String {
    format!("{user}@{host}:{port}")
}

/// Reads one line, dropping the trailing newline (and CR).
pub fn read_line(input: &mut dyn BufRead) -> Result<String> {
    let mut line = String::new();
    if input.read_line(&mut line).context("reading password from stdin")? == 0 {
        bail!("no password on stdin");
    }
    let trimmed = line.strip_suffix('\n').unwrap_or(&line);
    Ok(trimmed.strip_suffix('\r').unwrap_or(trimmed).to_owned())
}

/// Picks the password: explicit, then stdin, then keyring, then the prompt.
pub fn resolve(
    explicit: Option<String>,
    stdin: Option<&mut dyn BufRead>,
    store: &dyn Store,
    account: &str,
    prompt: impl FnOnce() -> Result<String>,
) -> Result<(String, Source)> {
    if let Some(p) = explicit {
        return Ok((p, Source::Explicit));
    }
    if let Some(input) = stdin {
        return Ok((read_line(input)?, Source::Stdin));
    }
    match store.get(account) {
        Ok(Some(p)) => return Ok((p, Source::Keyring)),
        Ok(None) => {}
        Err(e) => tracing::warn!("keyring unavailable: {e:#}"),
    }
    Ok((prompt()?, Source::Prompt))
}

/// Saving is opt-in: always with `save` (`--save-password`), otherwise only
/// a prompted password the user agrees to keep.
pub fn should_save(source: Source, save: bool, interactive: bool) -> bool {
    match source {
        Source::Keyring => false,
        _ if save => true,
        Source::Prompt => interactive,
        _ => false,
    }
}

/// Asks on the terminal whether to keep the password; defaults to no.
pub fn confirm_save(input: &mut dyn BufRead) -> bool {
    eprint!("Save password to keyring? [y/N] ");
    let mut line = String::new();
    input.read_line(&mut line).is_ok() && matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

/// Saves a working password if wanted, and drops a stored one the host
/// rejected so the next run prompts instead of failing again. `confirm` is
/// only asked when `save` wasn't given.
pub fn after_auth(
    store: &dyn Store,
    account: &str,
    password: &str,
    source: Source,
    ok: bool,
    save: bool,
    confirm: impl FnOnce() -> bool,
) {
    let result = match (ok, source) {
        (true, _) if should_save(source, save, true) && (save || confirm()) => {
            store.set(account, password).map(|()| {
                tracing::info!("saved password for {account} to keyring");
            })
        }
        (false, Source::Keyring) => store.delete(account).map(|_| {
            tracing::warn!("stored password for {account} was rejected; removed it from keyring");
        }),
        _ => Ok(()),
    };
    if let Err(e) = result {
        tracing::warn!("keyring unavailable: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Mem {
        map: Mutex<HashMap<String, String>>,
        broken: bool,
    }

    impl Store for Mem {
        fn get(&self, a: &str) -> Result<Option<String>> {
            if self.broken {
                bail!("no dbus");
            }
            Ok(self.map.lock().get(a).cloned())
        }
        fn set(&self, a: &str, p: &str) -> Result<()> {
            if self.broken {
                bail!("no dbus");
            }
            self.map.lock().insert(a.into(), p.into());
            Ok(())
        }
        fn delete(&self, a: &str) -> Result<bool> {
            if self.broken {
                bail!("no dbus");
            }
            Ok(self.map.lock().remove(a).is_some())
        }
    }

    const ACC: &str = "alice@mac:5900";

    fn stored(p: &str) -> Mem {
        let m = Mem::default();
        m.set(ACC, p).unwrap();
        m
    }

    fn no_prompt() -> Result<String> {
        panic!("prompted")
    }

    #[test]
    fn explicit_wins() {
        let m = stored("kr");
        let mut input: &[u8] = b"in\n";
        let r = resolve(Some("x".into()), Some(&mut input), &m, ACC, no_prompt).unwrap();
        assert_eq!(r, ("x".into(), Source::Explicit));
    }

    #[test]
    fn stdin_before_keyring() {
        let m = stored("kr");
        let mut input: &[u8] = b"p w\r\nnext\n";
        let r = resolve(None, Some(&mut input), &m, ACC, no_prompt).unwrap();
        assert_eq!(r, ("p w".into(), Source::Stdin));
    }

    #[test]
    fn stdin_without_newline_and_empty() {
        let mut input: &[u8] = b"pw";
        assert_eq!(read_line(&mut input).unwrap(), "pw");
        let mut input: &[u8] = b"";
        assert!(read_line(&mut input).is_err());
    }

    #[test]
    fn keyring_then_prompt() {
        let m = stored("kr");
        assert_eq!(resolve(None, None, &m, ACC, no_prompt).unwrap(), ("kr".into(), Source::Keyring));
        let m = Mem::default();
        let r = resolve(None, None, &m, ACC, || Ok("typed".into())).unwrap();
        assert_eq!(r, ("typed".into(), Source::Prompt));
    }

    #[test]
    fn broken_keyring_falls_back() {
        let m = Mem { broken: true, ..Default::default() };
        let r = resolve(None, None, &m, ACC, || Ok("typed".into())).unwrap();
        assert_eq!(r.1, Source::Prompt);
        after_auth(&m, ACC, "typed", Source::Prompt, true, true, no_confirm);
    }

    fn no_confirm() -> bool {
        panic!("asked to confirm")
    }

    #[test]
    fn save_is_opt_in() {
        let m = Mem::default();
        after_auth(&m, ACC, "bad", Source::Prompt, false, true, no_confirm);
        after_auth(&m, ACC, "env", Source::Explicit, true, false, no_confirm);
        after_auth(&m, ACC, "pipe", Source::Stdin, true, false, no_confirm);
        after_auth(&m, ACC, "declined", Source::Prompt, true, false, || false);
        assert!(m.get(ACC).unwrap().is_none());
        after_auth(&m, ACC, "typed", Source::Prompt, true, false, || true);
        assert_eq!(m.get(ACC).unwrap().as_deref(), Some("typed"));
        for (src, p) in [(Source::Stdin, "pipe"), (Source::Explicit, "env"), (Source::Prompt, "flag")] {
            after_auth(&m, ACC, p, src, true, true, no_confirm);
            assert_eq!(m.get(ACC).unwrap().as_deref(), Some(p));
        }
    }

    #[test]
    fn never_asks_for_keyring_or_non_tty() {
        assert!(!should_save(Source::Keyring, true, true));
        assert!(!should_save(Source::Prompt, false, false));
        assert!(should_save(Source::Prompt, false, true));
        assert!(!should_save(Source::Stdin, false, true));
    }

    #[test]
    fn confirm_defaults_to_no() {
        for (answer, want) in [(&b"\n"[..], false), (b"n\n", false), (b"", false), (b"y\n", true), (b"yes\n", true)] {
            let mut input = answer;
            assert_eq!(confirm_save(&mut input), want);
        }
    }

    #[test]
    fn rejected_keyring_password_is_removed() {
        let m = stored("old");
        after_auth(&m, ACC, "old", Source::Keyring, true, true, no_confirm);
        assert!(m.get(ACC).unwrap().is_some());
        after_auth(&m, ACC, "old", Source::Keyring, false, true, no_confirm);
        assert!(m.get(ACC).unwrap().is_none());
    }
}

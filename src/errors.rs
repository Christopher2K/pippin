//! User-facing failure messages. Lower layers raise [`Failure`] (or plain
//! io/auth errors) inside their `anyhow` chains; [`classify`] turns a chain
//! into a [`UserError`] whose `Display` is a short, actionable message. The
//! full chain stays available at debug level.

use std::io::ErrorKind;
use std::net::Ipv4Addr;

use thiserror::Error;

use crate::proto::auth::AuthError;

/// Typed markers for failures that a bare io error can't express.
#[derive(Debug, Error)]
pub enum Failure {
    #[error("server refused connection: {0}")]
    ServerRefused(String),
    #[error("server does not offer Apple auth (security types {0:?})")]
    NoAppleAuth(Vec<u8>),
    #[error("host declined the session request")]
    ShareDeclined,
    #[error("timed out waiting for the session to be shared or created")]
    ShareTimedOut,
    #[error("control connection lost")]
    ConnectionLost,
    /// The host never answered the media offer and no video followed.
    #[error("no media answer and no video")]
    NoMediaAnswer,
    #[error("no video received")]
    NoVideo,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UserError {
    #[error(
        "Can't reach {0}. Check the IP address, that the Mac is awake, \
         and that you're on the same network or VPN."
    )]
    Unreachable(String),
    #[error(
        "{0} refused the connection. Turn on Screen Sharing in \
         System Settings > General > Sharing, and check the IP address and port."
    )]
    Refused(String),
    #[error(
        "Timed out connecting to {0}. The Mac may be asleep, Screen Sharing may be off \
         (System Settings > General > Sharing), or the address may be wrong."
    )]
    TimedOut(String),
    #[error("{0} rejected the connection: {1}")]
    HostRejected(String, String),
    #[error("Authentication failed: wrong user name or password{}", reason_suffix(.0))]
    AuthFailed(Option<String>),
    #[error(
        "The user at {0}'s screen declined (or didn't answer) the request to share. \
         Try again, or use --session alt to log in separately."
    )]
    ShareDeclined(String),
    #[error(
        "{0} doesn't offer high-performance Screen Sharing. It needs macOS 14 or later \
         on Apple silicon, with High Performance enabled in the host's Screen Sharing settings."
    )]
    HighPerfUnavailable(String),
    #[error(
        "Connected to {0}, but no video arrived. A firewall or VPN is probably \
         blocking UDP ports 5900-5901 from the Mac."
    )]
    NoVideo(String),
    #[error("Connection to {0} lost.")]
    ConnectionLost(String),
    #[error("{0}")]
    Other(String),
}

fn reason_suffix(r: &Option<String>) -> String {
    r.as_ref().map(|r| format!(" ({r})")).unwrap_or_default()
}

/// Maps an error chain to the message shown to the user.
pub fn classify(e: &anyhow::Error, host: Ipv4Addr) -> UserError {
    let host = host.to_string();
    // `downcast_ref` also sees `.context(Failure::..)` layers, which
    // `chain()` items don't.
    if let Some(f) = e.downcast_ref::<Failure>() {
        return match f {
            Failure::ServerRefused(r) => UserError::HostRejected(host, r.clone()),
            Failure::NoAppleAuth(_) | Failure::NoMediaAnswer => UserError::HighPerfUnavailable(host),
            Failure::ShareDeclined | Failure::ShareTimedOut => UserError::ShareDeclined(host),
            Failure::ConnectionLost => UserError::ConnectionLost(host),
            Failure::NoVideo => UserError::NoVideo(host),
        };
    }
    for cause in e.chain() {
        if let Some(AuthError::Rejected(_)) = cause.downcast_ref::<AuthError>() {
            return UserError::AuthFailed(None);
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && let Some(u) = classify_io(io.kind(), &host)
        {
            return u;
        }
    }
    UserError::Other(format!("{e:#}"))
}

fn classify_io(kind: ErrorKind, host: &str) -> Option<UserError> {
    let host = host.to_string();
    Some(match kind {
        ErrorKind::ConnectionRefused => UserError::Refused(host),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => UserError::TimedOut(host),
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::AddrNotAvailable => {
            UserError::Unreachable(host)
        }
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe => UserError::ConnectionLost(host),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn io(kind: ErrorKind) -> anyhow::Error {
        anyhow::Error::new(std::io::Error::from(kind)).context("connecting to 10.0.0.2:5900")
    }

    #[test]
    fn io_kinds() {
        assert!(matches!(classify(&io(ErrorKind::ConnectionRefused), HOST), UserError::Refused(_)));
        assert!(matches!(classify(&io(ErrorKind::TimedOut), HOST), UserError::TimedOut(_)));
        assert!(matches!(classify(&io(ErrorKind::HostUnreachable), HOST), UserError::Unreachable(_)));
        assert!(matches!(classify(&io(ErrorKind::NetworkUnreachable), HOST), UserError::Unreachable(_)));
        assert!(matches!(classify(&io(ErrorKind::UnexpectedEof), HOST), UserError::ConnectionLost(_)));
        assert!(matches!(classify(&io(ErrorKind::PermissionDenied), HOST), UserError::Other(_)));
    }

    #[test]
    fn auth() {
        let e = anyhow::Error::new(AuthError::Rejected(1)).context("SRP authentication failed");
        assert_eq!(classify(&e, HOST), UserError::AuthFailed(None));
        assert!(UserError::AuthFailed(Some("locked".into())).to_string().ends_with("(locked)"));
        let e = anyhow::Error::new(Failure::ServerRefused("too many tries".into()));
        assert_eq!(classify(&e, HOST), UserError::HostRejected("10.0.0.2".into(), "too many tries".into()));
    }

    #[test]
    fn failures() {
        let c = |f| classify(&anyhow::Error::new(f), HOST);
        assert!(matches!(c(Failure::ShareDeclined), UserError::ShareDeclined(_)));
        assert!(matches!(c(Failure::ShareTimedOut), UserError::ShareDeclined(_)));
        assert!(matches!(c(Failure::NoAppleAuth(vec![2])), UserError::HighPerfUnavailable(_)));
        assert!(matches!(c(Failure::NoMediaAnswer), UserError::HighPerfUnavailable(_)));
        assert!(matches!(c(Failure::NoVideo), UserError::NoVideo(_)));
        assert_eq!(c(Failure::ConnectionLost).to_string(), "Connection to 10.0.0.2 lost.");
    }

    #[test]
    fn typed_marker_wins_over_inner_io() {
        let e = anyhow::Error::new(std::io::Error::from(ErrorKind::UnexpectedEof)).context(Failure::ShareDeclined);
        assert!(matches!(classify(&e, HOST), UserError::ShareDeclined(_)));
    }

    #[test]
    fn unknown_keeps_chain() {
        let e = anyhow::anyhow!("inner").context("outer");
        assert_eq!(classify(&e, HOST), UserError::Other("outer: inner".into()));
    }
}

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;

use crate::error::IdentityError;

/// The clock skew for a token, a certificate, and a ticket.
pub const MAX_SKEW: Duration = Duration::from_secs(60);

/// The longest life of a human SVID.
pub const MAX_USER_TTL: Duration = Duration::from_secs(15 * 60);

/// The longest life of an agent SVID.
pub const MAX_AGENT_TTL: Duration = Duration::from_secs(5 * 60);

pub(crate) const MAX_SKEW_SECS: u64 = 60;

/// The spike uses one year for the mini CA certificate.
pub(crate) const CA_LIFETIME_SECS: u64 = 365 * 24 * 60 * 60;

pub(crate) fn unix_time(now: SystemTime) -> Result<u64, IdentityError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| IdentityError::Time)
}

pub(crate) fn offset_from_unix(seconds: u64) -> Result<OffsetDateTime, IdentityError> {
    let seconds = i64::try_from(seconds).map_err(|_| IdentityError::Time)?;
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| IdentityError::Time)
}

/// Accept `now` when it is inside `[not_before - skew, not_after + skew]`.
///
/// Certificates keep this grace on both ends. Capability tickets use
/// [`ticket_in_window`] instead (strict end).
pub(crate) fn in_window(now: u64, not_before: u64, not_after: u64) -> Result<(), IdentityError> {
    if not_after < not_before {
        return Err(IdentityError::Time);
    }
    if now < not_before.saturating_sub(MAX_SKEW_SECS) {
        return Err(IdentityError::NotYetValid);
    }
    if now > not_after.saturating_add(MAX_SKEW_SECS) {
        return Err(IdentityError::Expired);
    }
    Ok(())
}

/// Accept `now` for a capability ticket: `not_before` allows ±60 s skew; `expires` is strict.
///
/// W25-45 / Crypto: do not give tickets the certificate end grace. `now == expires` is still
/// valid; `now > expires` is expired.
pub(crate) fn ticket_in_window(
    now: u64,
    not_before: u64,
    expires: u64,
) -> Result<(), IdentityError> {
    if expires < not_before {
        return Err(IdentityError::Time);
    }
    if now < not_before.saturating_sub(MAX_SKEW_SECS) {
        return Err(IdentityError::NotYetValid);
    }
    if now > expires {
        return Err(IdentityError::Expired);
    }
    Ok(())
}

pub(crate) fn whole_seconds(ttl: Duration) -> Result<u64, IdentityError> {
    if ttl.is_zero() || ttl.subsec_nanos() != 0 {
        return Err(IdentityError::Time);
    }
    Ok(ttl.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{in_window, ticket_in_window, MAX_SKEW_SECS};
    use crate::error::IdentityError;

    #[test]
    fn ticket_end_is_strict_certificate_end_keeps_grace() {
        let nbf = 1_000;
        let end = 2_000;
        // Ticket: now == expires OK; now == expires+1 refused.
        assert!(ticket_in_window(end, nbf, end).is_ok());
        assert_eq!(
            ticket_in_window(end + 1, nbf, end),
            Err(IdentityError::Expired)
        );
        // Ticket not_before still allows skew.
        assert!(ticket_in_window(nbf - MAX_SKEW_SECS, nbf, end).is_ok());
        assert_eq!(
            ticket_in_window(nbf - MAX_SKEW_SECS - 1, nbf, end),
            Err(IdentityError::NotYetValid)
        );
        // Certificate window still has end grace.
        assert!(in_window(end + MAX_SKEW_SECS, nbf, end).is_ok());
        assert_eq!(
            in_window(end + MAX_SKEW_SECS + 1, nbf, end),
            Err(IdentityError::Expired)
        );
    }
}

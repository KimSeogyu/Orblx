use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_identity::{IdentityError, WorkloadKind, MAX_SKEW};

use crate::error::CryptoError;

/// The longest QUIC connection life.
///
/// A rehandshake does not move this start time.
pub const MAX_SESSION: Duration = Duration::from_secs(2 * 60 * 60);

/// The 2 hour connection cap and the SVID rehandshake deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SessionLimit {
    connection_start: SystemTime,
    epoch_start: SystemTime,
    leaf_not_after: SystemTime,
    kind: WorkloadKind,
}

impl SessionLimit {
    /// Open a connection limit for one leaf.
    ///
    /// Reject an expired leaf.
    /// Reject a remaining life that is longer than `kind.max_ttl()`.
    pub fn open(
        now: SystemTime,
        kind: WorkloadKind,
        leaf_not_after: SystemTime,
    ) -> Result<Self, CryptoError> {
        check_leaf(now, kind, leaf_not_after)?;
        Ok(Self {
            connection_start: now,
            epoch_start: now,
            leaf_not_after,
            kind,
        })
    }

    /// Start the next epoch inside the same 2 hour cap.
    ///
    /// The workload kind stays the same.
    /// The connection start time stays the same.
    pub fn rehandshake(
        &self,
        now: SystemTime,
        kind: WorkloadKind,
        leaf_not_after: SystemTime,
    ) -> Result<Self, CryptoError> {
        if kind != self.kind {
            return Err(CryptoError::PeerUri);
        }
        if now < self.connection_start {
            return Err(CryptoError::SessionCap);
        }
        let hard = self.hard_expiry()?;
        if now >= hard {
            return Err(CryptoError::SessionCap);
        }
        check_leaf(now, kind, leaf_not_after)?;
        Ok(Self {
            connection_start: self.connection_start,
            epoch_start: now,
            leaf_not_after,
            kind,
        })
    }

    /// Return the workload kind for this connection.
    pub fn kind(&self) -> WorkloadKind {
        self.kind
    }

    /// Return the first handshake time.
    pub fn connection_start(&self) -> SystemTime {
        self.connection_start
    }

    /// Return the current epoch start.
    pub fn epoch_start(&self) -> SystemTime {
        self.epoch_start
    }

    /// Return the 2 hour cap instant.
    pub fn hard_expiry(&self) -> Result<SystemTime, CryptoError> {
        self.connection_start
            .checked_add(MAX_SESSION)
            .ok_or(CryptoError::SessionCap)
    }

    /// Return the earliest rehandshake deadline.
    pub fn deadline(&self) -> Result<SystemTime, CryptoError> {
        let hard = self.hard_expiry()?;
        let ttl_end = self
            .epoch_start
            .checked_add(self.kind.max_ttl())
            .ok_or(CryptoError::SessionCap)?;
        let before_leaf = self
            .leaf_not_after
            .checked_sub(MAX_SKEW)
            .unwrap_or(UNIX_EPOCH);
        Ok(min_time(hard, min_time(ttl_end, before_leaf)))
    }

    /// Return true when Datapath must run a new handshake before DATA.
    pub fn must_rehandshake(&self, now: SystemTime) -> Result<bool, CryptoError> {
        Ok(now >= self.deadline()?)
    }
}

fn check_leaf(
    now: SystemTime,
    kind: WorkloadKind,
    leaf_not_after: SystemTime,
) -> Result<(), CryptoError> {
    if leaf_not_after <= now {
        return Err(CryptoError::Identity(IdentityError::Expired));
    }
    let life = leaf_not_after
        .duration_since(now)
        .map_err(|_| CryptoError::SessionCap)?;
    if life > kind.max_ttl() {
        return Err(CryptoError::SessionCap);
    }
    Ok(())
}

fn min_time(left: SystemTime, right: SystemTime) -> SystemTime {
    if left <= right {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use orblx_identity::{WorkloadKind, MAX_SKEW};

    use super::{SessionLimit, MAX_SESSION};
    use crate::CryptoError;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn each_kind_uses_its_svid_cap_and_the_skew() {
        let now = at(1_700_000_000);
        let kinds = [
            WorkloadKind::User,
            WorkloadKind::Agent,
            WorkloadKind::Node,
            WorkloadKind::Coord,
        ];
        for kind in kinds {
            let leaf = now + kind.max_ttl();
            let limit = SessionLimit::open(now, kind, leaf).unwrap();
            assert_eq!(limit.deadline().unwrap(), leaf - MAX_SKEW);
            assert!(!limit.must_rehandshake(now).unwrap());
            assert!(limit.must_rehandshake(leaf - MAX_SKEW).unwrap());
            assert_eq!(
                SessionLimit::open(now, kind, leaf + Duration::from_secs(1)).unwrap_err(),
                CryptoError::SessionCap
            );
        }
    }

    #[test]
    fn a_leaf_inside_the_skew_window_is_due_at_once() {
        let now = at(1_700_000_000);
        let leaf = now + Duration::from_secs(30);
        let limit = SessionLimit::open(now, WorkloadKind::User, leaf).unwrap();
        assert!(limit.must_rehandshake(now).unwrap());
    }

    #[test]
    fn an_expired_leaf_is_rejected() {
        let now = at(1_700_000_000);
        let err = SessionLimit::open(now, WorkloadKind::Agent, now).unwrap_err();
        assert_eq!(
            err,
            CryptoError::Identity(orblx_identity::IdentityError::Expired)
        );
    }

    #[test]
    fn rehandshake_keeps_the_two_hour_start() {
        let start = at(1_700_000_000);
        let leaf = start + WorkloadKind::User.max_ttl();
        let first = SessionLimit::open(start, WorkloadKind::User, leaf).unwrap();
        let next_at = start + Duration::from_secs(14 * 60);
        let second = first
            .rehandshake(
                next_at,
                WorkloadKind::User,
                next_at + WorkloadKind::User.max_ttl(),
            )
            .unwrap();
        assert_eq!(second.connection_start(), start);
        assert_eq!(second.epoch_start(), next_at);
        assert_eq!(second.hard_expiry().unwrap(), start + MAX_SESSION);

        let late = start + MAX_SESSION;
        assert_eq!(
            first
                .rehandshake(late, WorkloadKind::User, late + Duration::from_secs(60))
                .unwrap_err(),
            CryptoError::SessionCap
        );
        let almost = start + MAX_SESSION - Duration::from_secs(1);
        let last = first
            .rehandshake(
                almost,
                WorkloadKind::User,
                almost + WorkloadKind::User.max_ttl(),
            )
            .unwrap();
        assert_eq!(last.deadline().unwrap(), start + MAX_SESSION);
        assert!(last.must_rehandshake(start + MAX_SESSION).unwrap());
        assert_eq!(
            first
                .rehandshake(
                    start - Duration::from_secs(1),
                    WorkloadKind::User,
                    start + Duration::from_secs(60)
                )
                .unwrap_err(),
            CryptoError::SessionCap
        );
        assert_eq!(
            first
                .rehandshake(
                    next_at,
                    WorkloadKind::Agent,
                    next_at + WorkloadKind::Agent.max_ttl()
                )
                .unwrap_err(),
            CryptoError::PeerUri
        );
    }
}

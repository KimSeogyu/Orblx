//! Receiver-side TCP checks against signed grants.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_audit::{AuditLog, DenyReason, SessionEvent, SessionIds};
use orblx_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
use orblx_identity::{
    sign_ticket, DenySet, MiniCa, ReceiverGrants, SpiffeId, TicketClaims, TicketFlags,
    TicketSigner, WorkloadKind, MAX_USER_TTL,
};

use crate::ipv4::encode_tcp_segment;
use crate::{HelloError, PeerGate};

/// Check one TCP packet on the receiver.
///
/// The function admits a capability ticket, then applies `grants`.
/// An allow returns true and writes no audit record.
/// A deny returns false and appends one deny record.
pub fn enforce_receiver_tcp(
    grants: &ReceiverGrants,
    src: &SpiffeId,
    dst: Ipv4Addr,
    port: u16,
    audit: &mut AuditLog,
) -> Result<bool, HelloError> {
    if src.kind() == WorkloadKind::Agent {
        return Err(HelloError::Node(
            "The receiver check uses a node SPIFFE ID or a user SPIFFE ID.".to_string(),
        ));
    }
    grants
        .check()
        .map_err(|err| HelloError::Node(err.to_string()))?;
    let now = SystemTime::now();
    let ca = MiniCa::generate(now).map_err(HelloError::Identity)?;
    let issued = ca
        .issue(src, now, MAX_USER_TTL, &DenySet::empty())
        .map_err(HelloError::Identity)?;
    let signer = TicketSigner::generate();
    let mac_key = [0x52u8; 32];
    let ring = ring_for(&ca, &signer, mac_key, now)?;
    let claims = broad_claims(src)?;
    let signed = sign_ticket(&signer, &claims).map_err(HelloError::Identity)?;
    let mac = ticket_mac(&mac_key, mac_input(&signed.bytes)).map_err(HelloError::Ticket)?;
    let mut gate = PeerGate::new();
    gate.bind_leaf(
        ca.trust_bundle(),
        &issued.certificate_der,
        now,
        &DenySet::empty(),
    )?;
    let hash = gate.admit_ticket(&ring, &signed.bytes, &mac, now, &DenySet::empty())?;
    gate.install_receiver_grants(grants.clone())?;
    let src_ip = Ipv4Addr::new(100, 64, 0, 2);
    let packet = encode_tcp_segment(src_ip, dst, 40_000, port, 0x10, b"acl")?;
    let frame = gate.encode_data(1, 0, hash, &packet)?;
    match gate.payload_from_data(&frame, now, &DenySet::empty()) {
        Ok(_) => Ok(true),
        Err(HelloError::DestinationDenied) => {
            let at_unix = unix_now()?;
            let event = SessionEvent::Deny {
                ids: SessionIds::receiver_acl(src.clone(), 1, hash),
                at_unix,
                reason: DenyReason::Destination,
            };
            audit
                .append(event)
                .map_err(|err| HelloError::Io(err.to_string()))?;
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

fn unix_now() -> Result<u64, HelloError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HelloError::Io("The clock is outside the Unix range.".to_string()))
}

fn broad_claims(subject: &SpiffeId) -> Result<TicketClaims, HelloError> {
    let start = unix_now()?;
    Ok(TicketClaims {
        issuer: SpiffeId::coord("coord").map_err(HelloError::Identity)?,
        subject: subject.clone(),
        not_before: start,
        expires: start.saturating_add(60),
        dst_cidr: "0.0.0.0/0".to_string(),
        proto: 6,
        dst_port: 1,
        flags: TicketFlags::none(),
    })
}

fn ring_for(
    ca: &MiniCa,
    signer: &TicketSigner,
    mac_key: [u8; 32],
    now: SystemTime,
) -> Result<TicketRing, HelloError> {
    let key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now.checked_sub(Duration::from_secs(60))
            .ok_or_else(|| HelloError::Io("The clock is outside the Unix range.".to_string()))?,
        now + Duration::from_secs(3600),
    )
    .map_err(HelloError::Ticket)?;
    TicketRing::single(key, ca.public_key()).map_err(HelloError::Ticket)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, UNIX_EPOCH};

    use orblx_audit::{verify_jsonl, AuditLog, DenyReason};
    use orblx_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
    use orblx_identity::{
        sign_agent_jit_ticket, DenySet, Ipv4Destination, IssueGate, MiniCa, MockOidc,
        ReceiverGrant, ReceiverGrants, SpiffeId, TicketSigner, MAX_AGENT_TTL, MOCK_OIDC_ISSUER,
    };

    use super::enforce_receiver_tcp;
    use crate::ipv4::encode_tcp_segment;
    use crate::{HelloError, PeerGate};

    fn grants_for_ssh() -> ReceiverGrants {
        ReceiverGrants {
            version: 1,
            receiver: "spiffe://orblx.local/node/box".to_string(),
            grants: vec![ReceiverGrant {
                src: "spiffe://orblx.local/node/mac".to_string(),
                proto: 6,
                port_start: 22,
                port_end: 22,
            }],
            reach: Vec::new(),
            filter: false,
            subnets: Vec::new(),
        }
    }

    #[test]
    fn mac_to_box_allows_ssh_and_denies_postgres() {
        let src = SpiffeId::node("mac").unwrap();
        let mut audit = AuditLog::new();
        let grants = grants_for_ssh();
        let allow =
            enforce_receiver_tcp(&grants, &src, Ipv4Addr::new(100, 64, 0, 1), 22, &mut audit)
                .unwrap();
        let deny = enforce_receiver_tcp(
            &grants,
            &src,
            Ipv4Addr::new(100, 64, 0, 1),
            5432,
            &mut audit,
        )
        .unwrap();
        assert!(allow);
        assert!(!deny);
        let text = audit.export_jsonl().unwrap();
        let checked = verify_jsonl(&text).unwrap();
        assert_eq!(checked.metrics.deny, 1);
        assert_eq!(checked.records, 1);
        assert_eq!(
            audit.records()[0].event.reason(),
            Some(DenyReason::Destination)
        );
        assert_eq!(
            audit.records()[0].event.ids().peer.as_uri(),
            "spiffe://orblx.local/node/mac"
        );
    }

    #[test]
    fn an_agent_jit_ticket_still_needs_a_grant() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let ca = MiniCa::generate(now).unwrap();
        let issuer_gate = IssueGate::new(ca, &oidc).unwrap();
        let parent = oidc
            .issue_id_token("seogyu-dev", now, Duration::from_secs(600))
            .unwrap();
        let agent = issuer_gate
            .issue_agent_svid(&parent, "helper", now, MAX_AGENT_TTL, &DenySet::empty())
            .unwrap();
        let signer = TicketSigner::generate();
        let mac_key = [0x42u8; 32];
        let ring = TicketRing::single(
            TicketKey::new(
                signer.verifier(),
                mac_key,
                now - Duration::from_secs(60),
                now + Duration::from_secs(3600),
            )
            .unwrap(),
            issuer_gate.ca_public_key(),
        )
        .unwrap();
        let dest = Ipv4Destination {
            addr: Ipv4Addr::new(100, 64, 0, 1),
            proto: 6,
            port: 22,
        };
        let jit = sign_agent_jit_ticket(
            &signer,
            &SpiffeId::coord("coord").unwrap(),
            &agent.svid.spiffe_id,
            now,
            Duration::from_secs(60),
            dest,
        )
        .unwrap();
        let mac = ticket_mac(&mac_key, mac_input(&jit.bytes)).unwrap();
        let mut gate = PeerGate::new();
        gate.bind_leaf(
            issuer_gate.trust_bundle(),
            &agent.svid.certificate_der,
            now,
            &DenySet::empty(),
        )
        .unwrap();
        let hash = gate
            .admit_ticket(&ring, &jit.bytes, &mac, now, &DenySet::empty())
            .unwrap();
        let packet = encode_tcp_segment(
            Ipv4Addr::new(100, 64, 0, 2),
            dest.addr,
            40_000,
            22,
            0x10,
            b"jit",
        )
        .unwrap();
        let frame = gate.encode_data(1, 0, hash, &packet).unwrap();
        assert!(gate
            .payload_from_data(&frame, now, &DenySet::empty())
            .is_ok());
        gate.install_receiver_grants(grants_for_ssh()).unwrap();
        let denied = gate
            .payload_from_data(&frame, now, &DenySet::empty())
            .unwrap_err();
        assert!(matches!(denied, HelloError::DestinationDenied));
    }
}

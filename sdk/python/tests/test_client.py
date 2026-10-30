"""Unit tests for the orblx agent SDK. They use a fake orblx command."""

import io
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orblx_agent import AgentClient, CoordTarget, GrantPending, OrblxError, redact  # noqa: E402

FAKE = str(Path(__file__).resolve().parent / "fake_orblx.py")


class FakeCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.state = Path(self.dir.name) / "state.json"
        self.write_state({"pending_fetches": 1})
        env = dict(os.environ, FAKE_ORBLX_STATE=str(self.state))
        self.client = AgentClient(
            CoordTarget(coord="100.64.0.1:443", state="/var/lib/orblx"),
            agent="bot",
            orblx=FAKE,
            _env=env,
        )
        self.log = io.StringIO()
        self.handler = logging.StreamHandler(self.log)
        logger = logging.getLogger("orblx_agent")
        logger.addHandler(self.handler)
        logger.setLevel(logging.DEBUG)

    def tearDown(self):
        logging.getLogger("orblx_agent").removeHandler(self.handler)
        self.dir.cleanup()

    def write_state(self, value):
        self.state.write_text(json.dumps(value), encoding="utf-8")

    def read_state(self):
        return json.loads(self.state.read_text(encoding="utf-8"))

    def grant(self, ttl_ms=60000, pending=1):
        self.write_state({"pending_fetches": pending, "ttl_ms": ttl_ms})
        grant_id = self.client.request_grant("b", "api", 8080, 60, path="/api")
        return self.client.wait_for_approval(grant_id, "/tmp/g", wait=10, poll=1)


class ClientTests(FakeCase):
    def test_request_and_wait_for_approval(self):
        grant = self.grant(pending=2)
        self.assertEqual(grant.grant_id, "0123456789abcdef")
        self.assertEqual(grant.port, 8080)
        self.assertEqual(grant.path, "/api")
        self.assertEqual(grant.approver, "spiffe://orblx.local/node/owner")
        calls = self.read_state()["calls"]
        request = calls[0]
        self.assertEqual(request[:3], ["agent", "grant", "request"])
        self.assertIn("--bundle", request)
        self.assertIn("/var/lib/orblx/bundle.pem", request)
        self.assertEqual(sum(1 for call in calls if call[2:3] == ["fetch"]), 3)

    def test_call_in_scope_and_out_of_scope(self):
        grant = self.grant()
        ok = self.client.call(grant, "/api/items?q=1")
        self.assertTrue(ok.ok)
        self.assertIn("upstream ok", ok.body)
        denied = self.client.call(grant, "/admin")
        self.assertEqual((denied.status, denied.reason), (403, "path"))
        self.assertFalse(denied.ok)

    def test_call_after_expiry_is_refused(self):
        grant = self.grant(ttl_ms=300)
        self.assertTrue(self.client.call(grant, "/api/items").ok)
        time.sleep(0.4)
        self.assertTrue(grant.expired())
        reply = self.client.call(grant, "/api/items")
        self.assertEqual((reply.status, reply.reason), (403, "expired"))

    def test_log_has_no_query_and_no_body(self):
        grant = self.grant()
        self.client.call(grant, "/api/items?token=abc", method="POST", body="secret body")
        text = self.log.getvalue()
        self.assertNotIn("token=abc", text)
        self.assertNotIn("secret body", text)
        self.assertIn("[11 bytes]", text)

    def test_pending_after_wait_raises(self):
        self.write_state({"pending_fetches": 1000})
        with self.assertRaises(GrantPending):
            self.client.wait_for_approval("0123456789abcdef", "/tmp/g", wait=1, poll=1)

    def test_bad_ttl_is_refused_before_a_call(self):
        with self.assertRaises(ValueError):
            self.client.request_grant("b", "api", 8080, 301)
        self.assertFalse(self.read_state().get("calls"))

    def test_error_and_log_hold_no_key(self):
        done = self.client._run(["broken"])
        err = self.client._fail(done, "The call")
        self.assertIsInstance(err, OrblxError)
        self.assertNotIn("MIIabc", str(err))
        self.grant()
        self.assertNotIn("PRIVATE KEY", self.log.getvalue())
        self.assertIn("grant 0123456789abcdef issued", self.log.getvalue())

    def test_missing_command(self):
        client = AgentClient(CoordTarget(coord="x:1"), agent="bot", orblx="/nonexistent/orblx")
        with self.assertRaises(OrblxError):
            client.request_grant("b", "api", 8080, 10)


class RedactTests(unittest.TestCase):
    def test_redact(self):
        text = (
            "a -----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY----- b "
            "T0JMWEFHVDEabc== ge1.secret.token orblx-agent-proof: xyz " + "A" * 130
        )
        out = redact(text)
        for needle in ["ABC", "T0JMWEFHVDE", "ge1.secret", "xyz", "A" * 130]:
            self.assertNotIn(needle, out)
        self.assertIn("orblx-agent-proof: [redacted]", out)
        self.assertEqual(redact("grant 0123456789abcdef issued"), "grant 0123456789abcdef issued")


if __name__ == "__main__":
    unittest.main()

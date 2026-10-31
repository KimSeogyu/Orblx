"""W25-39: agent-latency-split.py joins the agent, guard, and TUN traces of one request."""

import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "agent-latency-split.py")

TRACE = (
    "trace attempt 1 start_ms 1 send_ms 1 done_ms 1 result ok grant g1 send_us 1000000 "
    "seal_us 1010000 tcp_us 1012000 sent_us 1012100 reply_us 1060000 port 40000\n"
)
GUARD = (
    "agent use grant g1 service web port 8080 at_ms 1050\n"
    "agent timing peer_port 40000 accept_us 1011500 line_us 1052000 admit_us 1057000 "
    "upstream_us 1057500 reply_us 1057600 result ok\n"
)
DP_A = (
    "dp read at_us 1010100 src 100.64.0.2:40000 dst 100.64.0.3:8080 flags 02 len 0\n"
    "dp write at_us 1011900 src 100.64.0.3:8080 dst 100.64.0.2:40000 flags 12 len 0\n"
    "dp read at_us 1012050 src 100.64.0.2:40000 dst 100.64.0.3:8080 flags 18 len 900\n"
    "dp read at_us 1051000 src 100.64.0.2:40000 dst 100.64.0.3:8080 flags 18 len 1\n"
    "dp write at_us 1059000 src 100.64.0.3:8080 dst 100.64.0.2:40000 flags 18 len 9\n"
)
DP_B = (
    "dp write at_us 1011000 src 100.64.0.2:40000 dst 100.64.0.3:8080 flags 02 len 0\n"
    "dp read at_us 1011200 src 100.64.0.3:8080 dst 100.64.0.2:40000 flags 12 len 0\n"
    "dp write at_us 1013050 src 100.64.0.2:40000 dst 100.64.0.3:8080 flags 18 len 900\n"
    "dp write at_us 1051500 src 100.64.0.2:40000 dst 100.64.0.3:8080 flags 18 len 1\n"
    "dp read at_us 1058000 src 100.64.0.3:8080 dst 100.64.0.2:40000 flags 18 len 9\n"
)
PROBE = "probe n 1 start_us 2000000 connect_us 2001000 reply_us 2002000 port 41000 result ok\n"


class LatencySplitTest(unittest.TestCase):
    def test_one_request_gives_each_part(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name, text in (("t", TRACE), ("g", GUARD), ("a", DP_A), ("b", DP_B), ("p", PROBE)):
                path = os.path.join(tmp, name)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
                paths.append(path)
            out = subprocess.run(
                [sys.executable, SCRIPT, *paths], check=True, capture_output=True, text=True
            ).stdout
        line = next(x for x in out.splitlines() if x.startswith("split_attempt 1 "))
        parts = line.split()
        got = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}
        self.assertEqual(got["request"], "60.0")
        self.assertEqual(got["seal"], "10.0")
        self.assertEqual(got["g_admit"], "5.0")
        self.assertEqual(got["dp_syn"], "0.9")
        self.assertEqual(got["dp_synack"], "0.7")
        self.assertEqual(got["dp_req_max"], "1.0")
        self.assertEqual(got["dp_reply"], "1.0")
        self.assertEqual(got["req_pkts"], "2")
        self.assertEqual(got["req_spread"], "39.0")
        self.assertIn("split_rows agent 1 probe 1 req_pkts_2plus 1", out)
        self.assertIn("split probe_total_ms p50 2.0", out)


if __name__ == "__main__":
    unittest.main()

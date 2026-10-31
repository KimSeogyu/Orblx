"""W25-41: overlay-stage-split.py gives each datapath stage of one probe packet."""

import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "overlay-stage-split.py")
PKT = "src 100.64.0.2:41000 dst 100.64.0.3:9090 flags 18 len 5 seq 7"
DP_A = "\n".join([
    f"dp read at_us 1000000 {PKT}",
    f"dp tun_dequeued at_us 1000100 {PKT}",
    f"dp link_dequeued at_us 1000300 {PKT}",
    f"dp stream_written at_us 1000400 {PKT}",
    "udp udp_send at_us 1000600 bytes 120 datagrams 1",
]) + "\n"
DP_B = "\n".join([
    "udp udp_recv at_us 1000700 bytes 120 datagrams 1",
    f"dp frame_read at_us 1001700 {PKT}",
    f"dp ticket_checked at_us 1001800 {PKT}",
    f"dp tun_enqueue at_us 1001850 {PKT}",
    f"dp write at_us 1002000 {PKT}",
]) + "\n"
PROBE = "probe n 1 start_us 0 connect_us 1000 reply_us 4000 port 41000 result ok\n"


class OverlayStageSplitTest(unittest.TestCase):
    def test_one_packet_gives_each_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name, text in (("a", DP_A), ("b", DP_B), ("p", PROBE)):
                path = os.path.join(tmp, name)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
                paths.append(path)
            out = subprocess.run(
                [sys.executable, SCRIPT, *paths, "t"], check=True, capture_output=True, text=True
            ).stdout
        self.assertIn("stage_rows t a_to_b 1 b_to_a 0", out)
        self.assertIn("stage t a_to_b tun_hop_ms p50 0.100 ", out)
        self.assertIn("stage t a_to_b route_hop_ms p50 0.200 ", out)
        self.assertIn("stage t a_to_b quic_send_ms p50 0.300 ", out)
        self.assertIn("stage t a_to_b wire_ms p50 0.100 ", out)
        self.assertIn("stage t a_to_b quic_recv_ms p50 1.000 ", out)
        self.assertIn("stage t a_to_b ticket_ms p50 0.100 ", out)
        self.assertIn("stage t a_to_b one_way_ms p50 2.000 ", out)
        self.assertIn("stage t probe_rtt_ms p50 3.000 ", out)
        self.assertIn("w25_41_target t one_way_p50_ms 2.000 (<= 2) one_way_p99_ms 2.000 (<= 10) "
                      "probe_rtt_p99_ms 3.000 (<= 20) probe_failed 0 result met", out)


if __name__ == "__main__":
    unittest.main()

"""W25-46 overlap audit.

A lock holder is one pair of acquire time and pid. A second log with the same
pair is a copy. The end of a hold is the release time or the proof_cancel time,
the earlier one when both exist. A proof_plan_end line is a nominal end. The
audit records that line and does not use it as the end.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime

ACQUIRE_RE = re.compile(r"^proof_lock (\S+) acquired at (\S+)")
RELEASE_RE = re.compile(r"^proof_lock (\S+) released at (\S+) pid=(\d+)")
CANCEL_RE = re.compile(r"^proof_cancel (\S+)(?: pid=(\d+))?")
PLAN_RE = re.compile(r"^proof_plan_end (\S+)")
CONTEXT_RE = re.compile(
    r"^proof_context (\S+) phase start .* other_orblx_containers (\d+)"
)
CONTENTION_RE = re.compile(
    r"^proof_contention (\S+) samples \d+ contended_samples (\d+)"
)

WINDOW_START = "2026-11-05T09:10:00.000+0900"
WINDOW_END = "2026-11-05T09:15:00.000+0900"
SOAK_LABEL = "coord-cert-soak"


@dataclass
class Run:
    label: str
    acquire: datetime
    source: str
    pid: int | None = None
    release: datetime | None = None
    cancel: datetime | None = None
    plan_end: datetime | None = None
    other: int | None = None
    contended: int | None = None


def parse_ts(token: str) -> datetime:
    text = token.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    zoned = re.fullmatch(r"(.+)([+-]\d{2}):(\d{2})", text)
    if zoned:
        text = zoned.group(1) + zoned.group(2) + zoned.group(3)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(f"bad time {token}")


def fmt_ts(value: datetime) -> str:
    text = value.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    return text[:-8] + text[-5:]


def real_end(run: Run) -> datetime | None:
    ends = [item for item in (run.release, run.cancel) if item is not None]
    if not ends:
        return None
    return min(ends)


def real_end_source(run: Run) -> str:
    end = real_end(run)
    if end is None:
        return "none"
    if run.cancel is not None and run.cancel == end:
        return "proof_cancel"
    if run.release is not None and run.release == end:
        return "release"
    return "none"


def parse_log(path: str) -> list[Run]:
    runs: list[Run] = []
    current: Run | None = None
    name = os.path.basename(path)
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            acquired = ACQUIRE_RE.match(line)
            if acquired:
                if current is not None:
                    runs.append(current)
                current = Run(
                    label=acquired.group(1),
                    acquire=parse_ts(acquired.group(2)),
                    source=name,
                )
                continue
            if current is None:
                continue
            released = RELEASE_RE.match(line)
            if released and released.group(1) == current.label:
                current.release = parse_ts(released.group(2))
                current.pid = int(released.group(3))
                continue
            cancelled = CANCEL_RE.match(line)
            if cancelled:
                current.cancel = parse_ts(cancelled.group(1))
                if cancelled.group(2):
                    current.pid = int(cancelled.group(2))
                continue
            planned = PLAN_RE.match(line)
            if planned:
                current.plan_end = parse_ts(planned.group(1))
                continue
            context = CONTEXT_RE.match(line)
            if context and context.group(1) == current.label:
                current.other = int(context.group(2))
                continue
            contention = CONTENTION_RE.match(line)
            if contention and contention.group(1) == current.label:
                current.contended = int(contention.group(2))
    if current is not None:
        runs.append(current)
    return runs


def load_dir(log_dir: str) -> list[Run]:
    names = sorted(
        name
        for name in os.listdir(log_dir)
        if name.endswith(".log") and os.path.isfile(os.path.join(log_dir, name))
    )
    runs: list[Run] = []
    for name in names:
        runs.extend(parse_log(os.path.join(log_dir, name)))
    return runs


def dedupe_key(run: Run) -> tuple[datetime, int] | None:
    if run.pid is None:
        return None
    return (run.acquire, run.pid)


def dedupe(runs: list[Run]) -> list[Run]:
    seen: set[tuple[datetime, int]] = set()
    kept: list[Run] = []
    for run in runs:
        key = dedupe_key(run)
        if key is None:
            kept.append(run)
            continue
        if key in seen:
            continue
        seen.add(key)
        kept.append(run)
    return kept


def overlap_pair_count(runs: list[Run], *, use_dedupe: bool) -> int:
    chosen = dedupe(runs) if use_dedupe else list(runs)
    closed: list[tuple[Run, datetime]] = []
    for run in chosen:
        end = real_end(run)
        if end is None:
            continue
        closed.append((run, end))
    count = 0
    for index, (left, left_end) in enumerate(closed):
        for right, right_end in closed[index + 1 :]:
            if left.acquire < right_end and right.acquire < left_end:
                count += 1
    return count


def in_window(run: Run, start: datetime, end: datetime) -> bool:
    return start <= run.acquire < end


def container_verdict(run: Run) -> tuple[str, str]:
    other_busy = run.other is not None and run.other > 0
    samples_busy = run.contended is not None and run.contended > 0
    if other_busy or samples_busy:
        if other_busy:
            return "INVALID", "soak_containers_still_running"
        return "INVALID", "contended_samples"
    if run.other is None and run.contended is None:
        return "UNKNOWN", "no_container_sample"
    return "VALID_for_container_overlap", "clear"


def _soak(runs: list[Run]) -> Run | None:
    for run in runs:
        if run.label == SOAK_LABEL:
            return run
    return None


def render(runs: list[Run]) -> str:
    kept = dedupe(runs)
    start = parse_ts(WINDOW_START)
    end = parse_ts(WINDOW_END)
    lines = [
        "w25-46 overlap audit",
        "dedupe_key=acquire_time+pid",
        f"runs_before={len(runs)}",
        f"runs_after_dedupe={len(kept)}",
        f"duplicate_logs={len(runs) - len(kept)}",
    ]
    soak = _soak(kept)
    if soak is None:
        lines.append("soak_label=")
        lines.append("soak_pid=")
        lines.append("soak_nominal_end=")
        lines.append("soak_real_end=")
        lines.append("soak_real_end_source=none")
    else:
        lines.append(f"soak_label={soak.label}")
        lines.append(f"soak_pid={soak.pid if soak.pid is not None else ''}")
        lines.append(
            "soak_nominal_end="
            + (fmt_ts(soak.plan_end) if soak.plan_end is not None else "")
        )
        soak_end = real_end(soak)
        lines.append("soak_real_end=" + (fmt_ts(soak_end) if soak_end is not None else ""))
        lines.append(f"soak_real_end_source={real_end_source(soak)}")
    lines.append(f"overlap_pairs={overlap_pair_count(runs, use_dedupe=True)}")
    lines.append(f"rejudge_window={WINDOW_START}/{WINDOW_END}")
    window = [run for run in kept if in_window(run, start, end)]
    window.sort(key=lambda run: (run.acquire, run.label, run.source))
    for run in window:
        verdict, reason = container_verdict(run)
        other = "" if run.other is None else str(run.other)
        contended = "" if run.contended is None else str(run.contended)
        lines.append(
            "rejudge "
            f"{run.label} acquire={fmt_ts(run.acquire)} log={run.source} "
            f"verdict={verdict} reason={reason} "
            f"contended_samples={contended} other={other}"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="W25-46 overlap audit")
    parser.add_argument("log_dir")
    parser.add_argument("-o", "--output", default="")
    args = parser.parse_args(argv)
    text = render(load_dir(args.log_dir))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

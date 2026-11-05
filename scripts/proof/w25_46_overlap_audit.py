"""W25-46 overlap audit.

A lock holder is one acquire. When the acquire line has a pid, a second log with
the same acquire time and the same pid is a copy. When the acquire line has no
pid, a second log with the same label and the same acquire time is a copy.

The end of a hold is the earliest of the release time, the proof_cancel time,
and, for coord-cert-soak, the next holder's acquire time. A proof_plan_end line
is a nominal end. The audit records that line and does not use it as the end.
A lock_released line in the cancel log is cancel-script latency. It is not the
flock end.

The default cutoff is the time of commit 393f7df (2026-10-31T17:23:11+09:00).
Only acquires after that time are counted. --until counts acquires at or before
that time. The scan reads .log files in the directory and in subdirectories.
A path in the record is relative to the log directory.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta

ACQUIRE_RE = re.compile(r"^proof_lock (\S+) acquired at (\S+)")
RELEASE_RE = re.compile(r"^proof_lock (\S+) released at (\S+)(?: pid=(\d+))?")
CANCEL_WORD_FIRST_RE = re.compile(r"^proof_cancel (\S+)(?: pid=(\d+))?")
CANCEL_TIME_FIRST_RE = re.compile(
    r"^(\S+) proof_cancel\b.*?holder_pid=(\d+)|"
    r"^(\S+) proof_cancel\b"
)
PLAN_RE = re.compile(r"^proof_plan_end (\S+)")
CONTEXT_RE = re.compile(
    r"^proof_context (\S+) phase (\S+) time (\S+) .* "
    r"other_orblx_containers (\d+) groups (\S+)"
)
CONTENTION_RE = re.compile(
    r"^proof_contention (\S+) samples (\d+) contended_samples (\d+)"
)
HOLDER_RE = re.compile(r"holder: label=(\S+) pid=(\d+)\b.*? since=(\S+)")
LOCK_RELEASED_RE = re.compile(
    r"^(\S+) lock_released\b(?:.*? next_holder=(\S+))?(?:.*? pid=(\d+))?"
)

WINDOW_START = "2026-11-05T09:10:00.000+0900"
WINDOW_END = "2026-11-05T09:15:00.000+0900"
# Commit 393f7df. Acquires after this time are in the audit.
DEFAULT_CUTOFF = "2026-10-31T17:23:11+09:00"
SOAK_LABEL = "coord-cert-soak"
PID_MATCH = timedelta(seconds=5)
VERDICT = (
    "No real 2-holder flock window. "
    "Container overlap: yes (policy-scale 09:10:35 INVALID)."
)


@dataclass
class Run:
    label: str
    acquire: datetime
    source: str
    acquire_line: int
    pid: int | None = None
    release: datetime | None = None
    release_line: int | None = None
    cancel: datetime | None = None
    cancel_source: str = ""
    cancel_line: int | None = None
    plan_end: datetime | None = None
    other: int | None = None
    contended: int | None = None
    groups: str = ""
    start_time: datetime | None = None
    start_line: int | None = None
    contention_line: int | None = None
    lock_released: datetime | None = None
    lock_released_source: str = ""
    lock_released_line: int | None = None


@dataclass
class HolderSeen:
    label: str
    pid: int
    since: datetime


@dataclass
class LooseCancel:
    when: datetime
    pid: int | None
    source: str
    line: int


@dataclass
class LooseLockReleased:
    when: datetime
    source: str
    line: int


@dataclass
class Parsed:
    runs: list[Run] = field(default_factory=list)
    holders: list[HolderSeen] = field(default_factory=list)
    cancels: list[LooseCancel] = field(default_factory=list)
    lock_released: list[LooseLockReleased] = field(default_factory=list)


def parse_ts(token: str) -> datetime:
    text = token.strip().rstrip(".,")
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


def _note_release(run: Run, when: datetime, line: int, pid: int | None) -> None:
    if run.release is None or when < run.release:
        run.release = when
        run.release_line = line
    if pid is not None and run.pid is None:
        run.pid = pid


def _note_cancel(run: Run, when: datetime, source: str, line: int, pid: int | None) -> None:
    if run.cancel is None or when < run.cancel:
        run.cancel = when
        run.cancel_source = source
        run.cancel_line = line
    elif run.cancel_source == "" or (
        "cancel" in source and "cancel" not in run.cancel_source
    ):
        run.cancel_source = source
        run.cancel_line = line
    if pid is not None:
        run.pid = pid


def parse_log(path: str, source: str = "") -> Parsed:
    parsed = Parsed()
    current: Run | None = None
    name = source or os.path.basename(path)
    with open(path, encoding="utf-8", errors="replace") as handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.strip()
            holder = HOLDER_RE.search(line)
            if holder:
                parsed.holders.append(
                    HolderSeen(
                        label=holder.group(1),
                        pid=int(holder.group(2)),
                        since=parse_ts(holder.group(3)),
                    )
                )
            acquired = ACQUIRE_RE.match(line)
            if acquired:
                if current is not None:
                    parsed.runs.append(current)
                current = Run(
                    label=acquired.group(1),
                    acquire=parse_ts(acquired.group(2)),
                    source=name,
                    acquire_line=number,
                )
                continue
            released = RELEASE_RE.match(line)
            if released and current is not None and released.group(1) == current.label:
                pid = int(released.group(3)) if released.group(3) else None
                _note_release(current, parse_ts(released.group(2)), number, pid)
                continue
            word_first = CANCEL_WORD_FIRST_RE.match(line)
            if word_first:
                pid = int(word_first.group(2)) if word_first.group(2) else None
                when = parse_ts(word_first.group(1))
                if current is not None:
                    _note_cancel(current, when, name, number, pid)
                else:
                    parsed.cancels.append(LooseCancel(when, pid, name, number))
                continue
            time_first = CANCEL_TIME_FIRST_RE.match(line)
            if time_first:
                when = parse_ts(time_first.group(1) or time_first.group(3))
                pid = int(time_first.group(2)) if time_first.group(2) else None
                if current is not None:
                    _note_cancel(current, when, name, number, pid)
                parsed.cancels.append(LooseCancel(when, pid, name, number))
                continue
            locked = LOCK_RELEASED_RE.match(line)
            if locked:
                parsed.lock_released.append(
                    LooseLockReleased(
                        when=parse_ts(locked.group(1)),
                        source=name,
                        line=number,
                    )
                )
                continue
            planned = PLAN_RE.match(line)
            if planned and current is not None:
                current.plan_end = parse_ts(planned.group(1))
                continue
            context = CONTEXT_RE.match(line)
            if context and current is not None and context.group(1) == current.label:
                if context.group(2) == "start":
                    current.start_time = parse_ts(context.group(3))
                    current.start_line = number
                    current.other = int(context.group(4))
                    current.groups = context.group(5)
                continue
            contention = CONTENTION_RE.match(line)
            if contention and current is not None and contention.group(1) == current.label:
                current.contended = int(contention.group(3))
                current.contention_line = number
    if current is not None:
        parsed.runs.append(current)
    return parsed


def log_paths(log_dir: str) -> list[tuple[str, str]]:
    root = os.path.abspath(log_dir)
    found: list[tuple[str, str]] = []
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(".log"):
                continue
            path = os.path.join(current, name)
            if not os.path.isfile(path):
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            found.append((path, rel))
    return found


def load_dir(log_dir: str) -> list[Run]:
    parsed = Parsed()
    for path, rel in log_paths(log_dir):
        one = parse_log(path, source=rel)
        parsed.runs.extend(one.runs)
        parsed.holders.extend(one.holders)
        parsed.cancels.extend(one.cancels)
        parsed.lock_released.extend(one.lock_released)
    _attach_pids(parsed.runs, parsed.holders)
    _attach_loose_cancels(parsed.runs, parsed.cancels)
    _attach_lock_released(parsed.runs, parsed.lock_released)
    return parsed.runs


def _attach_pids(runs: list[Run], seen: list[HolderSeen]) -> None:
    for run in runs:
        if run.pid is not None:
            continue
        best: HolderSeen | None = None
        best_gap: float | None = None
        for item in seen:
            if item.label != run.label:
                continue
            delta = (run.acquire - item.since).total_seconds()
            if delta < -1 or delta > PID_MATCH.total_seconds():
                continue
            gap = abs(delta)
            if best_gap is None or gap < best_gap:
                best = item
                best_gap = gap
        if best is not None:
            run.pid = best.pid


def _soak_for_time(runs: list[Run], when: datetime) -> Run | None:
    soaks = [
        run
        for run in runs
        if run.label == SOAK_LABEL and run.acquire <= when
    ]
    if not soaks:
        return None
    return max(soaks, key=lambda run: run.acquire)


def _prefer_cancel_file(items: list[LooseCancel]) -> LooseCancel:
    named = [item for item in items if "cancel" in item.source]
    pool = named or items
    return min(pool, key=lambda item: (item.when, item.line, item.source))


def _attach_loose_cancels(runs: list[Run], cancels: list[LooseCancel]) -> None:
    if not cancels:
        return
    chosen = _prefer_cancel_file(cancels)
    target = _soak_for_time(runs, chosen.when)
    if target is None:
        return
    target.cancel = chosen.when
    target.cancel_source = chosen.source
    target.cancel_line = chosen.line
    if chosen.pid is not None:
        target.pid = chosen.pid


def _attach_lock_released(runs: list[Run], rows: list[LooseLockReleased]) -> None:
    if not rows:
        return
    named = [row for row in rows if "cancel" in row.source]
    pool = named or rows
    chosen = min(pool, key=lambda row: (row.when, row.line, row.source))
    target = _soak_for_time(runs, chosen.when)
    if target is None:
        return
    target.lock_released = chosen.when
    target.lock_released_source = chosen.source
    target.lock_released_line = chosen.line


def dedupe_key(run: Run) -> tuple[str, datetime, int | str]:
    if run.pid is not None:
        return ("pid", run.acquire, run.pid)
    return ("label", run.label, run.acquire)


def dedupe(runs: list[Run]) -> list[Run]:
    seen_pid: set[tuple[datetime, int]] = set()
    seen_label: set[tuple[str, datetime]] = set()
    kept: list[Run] = []
    for run in runs:
        label_key = (run.label, run.acquire)
        pid_key = (run.acquire, run.pid) if run.pid is not None else None
        if label_key in seen_label or (pid_key is not None and pid_key in seen_pid):
            continue
        seen_label.add(label_key)
        if pid_key is not None:
            seen_pid.add(pid_key)
        kept.append(run)
    return kept


def after_cutoff(runs: list[Run], cutoff: datetime) -> list[Run]:
    return [run for run in runs if run.acquire > cutoff]


def at_or_before(runs: list[Run], until: datetime) -> list[Run]:
    return [run for run in runs if run.acquire <= until]


def next_holder_acquire(run: Run, runs: list[Run]) -> datetime | None:
    later = [item.acquire for item in runs if item.acquire > run.acquire]
    if not later:
        return None
    return min(later)


def end_and_source(run: Run, runs: list[Run]) -> tuple[datetime | None, str]:
    tagged: list[tuple[datetime, str]] = []
    if run.cancel is not None:
        tagged.append((run.cancel, "proof_cancel"))
    if run.release is not None:
        tagged.append((run.release, "release"))
    if run.label == SOAK_LABEL:
        nxt = next_holder_acquire(run, runs)
        if nxt is not None:
            tagged.append((nxt, "next_acquire"))
    if not tagged:
        return None, "none"
    best = min(item[0] for item in tagged)
    order = {"proof_cancel": 0, "release": 1, "next_acquire": 2}
    winners = [source for when, source in tagged if when == best]
    winners.sort(key=lambda source: order[source])
    return best, winners[0]


def overlap_pair_count(runs: list[Run], *, use_dedupe: bool) -> int:
    chosen = dedupe(runs) if use_dedupe else list(runs)
    closed: list[tuple[Run, datetime]] = []
    for run in chosen:
        end, _source = end_and_source(run, chosen)
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
    soaks = [run for run in runs if run.label == SOAK_LABEL]
    if not soaks:
        return None
    cancelled = [run for run in soaks if run.cancel is not None]
    pool = cancelled or soaks
    return max(pool, key=lambda run: run.acquire)


def _cite(name: str, line: int | None) -> str:
    if line is None:
        return name
    return f"{name}:{line}"


def render(
    runs: list[Run],
    cutoff: datetime | None = None,
    source_dir: str = "",
    until: datetime | None = None,
) -> str:
    if cutoff is None:
        cutoff = parse_ts(DEFAULT_CUTOFF)
    selected = after_cutoff(runs, cutoff)
    if until is not None:
        selected = at_or_before(selected, until)
    kept = dedupe(selected)
    start = parse_ts(WINDOW_START)
    end = parse_ts(WINDOW_END)
    lines = [
        "w25-46 overlap audit",
        "dedupe_key=acquire_time+pid|label+acquire",
        f"cutoff={fmt_ts(cutoff)}",
        "until=" + (fmt_ts(until) if until is not None else ""),
        f"runs_before={len(selected)}",
        f"runs_after_dedupe={len(kept)}",
        f"duplicate_logs={len(selected) - len(kept)}",
    ]
    if source_dir:
        lines.append(f"source_dir={source_dir.rstrip('/')}")
    soak = _soak(kept)
    soak_end: datetime | None = None
    soak_source = "none"
    if soak is None:
        lines.append("soak_label=")
        lines.append("soak_pid=")
        lines.append("soak_nominal_end=")
        lines.append("soak_real_end=")
        lines.append("soak_real_end_source=none")
    else:
        soak_end, soak_source = end_and_source(soak, kept)
        lines.append(f"soak_label={soak.label}")
        lines.append(f"soak_pid={soak.pid if soak.pid is not None else ''}")
        lines.append(
            "soak_nominal_end="
            + (fmt_ts(soak.plan_end) if soak.plan_end is not None else "")
        )
        lines.append("soak_real_end=" + (fmt_ts(soak_end) if soak_end is not None else ""))
        lines.append(f"soak_real_end_source={soak_source}")
        if soak.cancel is not None and soak.cancel_line is not None:
            lines.append(
                "soak_cancel_record="
                + _cite(soak.cancel_source or soak.source, soak.cancel_line)
            )
    pair_count = overlap_pair_count(selected, use_dedupe=True)
    lines.append(f"overlap_pairs={pair_count}")
    lines.append(f"rejudge_window={WINDOW_START}/{WINDOW_END}")
    window = [run for run in kept if in_window(run, start, end)]
    window.sort(key=lambda run: (run.acquire, run.label, run.source))
    invalid_policy: Run | None = None
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
        if (
            invalid_policy is None
            and verdict == "INVALID"
            and run.label.startswith("policy-scale")
        ):
            invalid_policy = run
    if soak is not None and soak.cancel is not None and invalid_policy is not None:
        lines.append(
            "timeline proof_cancel time="
            f"{fmt_ts(soak.cancel)} path={_cite(soak.cancel_source or soak.source, soak.cancel_line)}"
        )
        lines.append(
            "timeline flock_free_at_or_before time="
            f"{fmt_ts(invalid_policy.acquire)} "
            f"path={_cite(invalid_policy.source, invalid_policy.acquire_line)}"
        )
        if invalid_policy.start_time is not None:
            lines.append(
                "timeline containers_still_up time="
                f"{fmt_ts(invalid_policy.start_time)} "
                f"other_orblx_containers={invalid_policy.other} "
                f"groups={invalid_policy.groups} "
                f"path={_cite(invalid_policy.source, invalid_policy.start_line)}"
            )
        if soak.lock_released is not None:
            lines.append(
                "timeline lock_released time="
                f"{fmt_ts(soak.lock_released)} "
                f"path={_cite(soak.lock_released_source, soak.lock_released_line)} "
                "note=after_flock_free cancel_script_log_latency"
            )
        if pair_count == 0 and soak_end is not None and soak_end <= invalid_policy.acquire:
            lines.append(VERDICT)
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="W25-46 overlap audit")
    parser.add_argument("log_dir")
    parser.add_argument("-o", "--output", default="")
    parser.add_argument("--cutoff", default=DEFAULT_CUTOFF)
    parser.add_argument("--until", default="")
    parser.add_argument(
        "--source-dir",
        default="",
        help="Directory named on the source_dir line. The default is log_dir.",
    )
    args = parser.parse_args(argv)
    source_dir = args.source_dir or os.path.abspath(args.log_dir)
    until = parse_ts(args.until) if args.until else None
    text = render(
        load_dir(args.log_dir),
        cutoff=parse_ts(args.cutoff),
        source_dir=source_dir,
        until=until,
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

import datetime
import os
import sys
import time
from typing import Any, Dict

# Make sibling imports work when running from repo root:
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from checkpoint import load_checkpoint, save_checkpoint, is_completed, mark_completed
from parser_fgt_v1 import parse_fortigate_line
from sink_jsonl import append_event, append_dlq, append_metrics
from source_file import ACTIVE_PATH, list_rotated_files, stat_file, read_whole_file_lines, follow_active_binary, active_inode
from metrics import MetricsWindow

# Hard-coded behavior knobs (no CLI args)
METRICS_INTERVAL_SEC = 10
CHECKPOINT_FLUSH_INTERVAL_SEC = 2

def _now_ts() -> int:
    return int(time.time())

def _ingest_ts() -> int:
    return int(time.time())

def _ensure_dirs() -> None:
    os.makedirs("/data/fortigate/parsed", exist_ok=True)

def _write_dlq(ck: Dict[str, Any], reason: str, raw: str, source: Dict[str, Any]) -> None:
    dlq = {
        "schema_version": 1,
        "ingest_ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reason": reason,
        "source": source,
        "raw": raw
    }
    try:
        append_dlq(_ingest_ts(), dlq)
        ck["counters"]["dlq_out_total"] += 1
        ck["counters"]["parse_fail_total"] += 1
    except Exception:
        ck["counters"]["write_fail_total"] += 1

def _write_event(ck: Dict[str, Any], event: Dict[str, Any], source: Dict[str, Any]) -> None:
    event["ingest_ts"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event["source"] = {"path": source.get("path"), "inode": source.get("inode"), "offset": source.get("offset")}
    try:
        append_event(_ingest_ts(), event)
        ck["counters"]["events_out_total"] += 1
        if event.get("event_ts"):
            ck["active"]["last_event_ts_seen"] = event["event_ts"]
    except Exception:
        ck["counters"]["write_fail_total"] += 1

def process_rotated_files(ck: Dict[str, Any]) -> None:
    for path in list_rotated_files():
        try:
            inode, size, mtime = stat_file(path)
        except FileNotFoundError:
            continue

        if is_completed(ck, path, inode, size, mtime):
            continue

        for line, src in read_whole_file_lines(path):
            raw = line
            ck["counters"]["lines_in_total"] += 1
            ck["counters"]["bytes_in_total"] += len(raw.encode("utf-8", errors="replace"))

            now_year = datetime.datetime.now().year
            event, dlq = parse_fortigate_line(raw, now_year)
            if event is not None:
                _write_event(ck, event, src)
            else:
                reason = dlq.get("reason", "parse_fail") if dlq else "parse_fail"
                _write_dlq(ck, reason, raw, src)

        mark_completed(ck, path, inode, size, mtime)

def process_active_tail(ck: Dict[str, Any], max_seconds: int = 2) -> None:
    start = time.time()

    cur_inode = active_inode()
    if cur_inode is None:
        time.sleep(0.2)
        return

    if ck["active"].get("inode") is None:
        ck["active"]["inode"] = cur_inode
        ck["active"]["offset"] = 0

    if ck["active"]["inode"] != cur_inode:
        ck["active"]["inode"] = cur_inode
        ck["active"]["offset"] = 0

    offset = int(ck["active"].get("offset", 0))

    for line, new_offset in follow_active_binary(offset):
        new_inode = active_inode()
        if new_inode is not None and new_inode != ck["active"]["inode"]:
            ck["active"]["inode"] = new_inode
            ck["active"]["offset"] = 0
            break

        raw = line
        ck["counters"]["lines_in_total"] += 1
        ck["counters"]["bytes_in_total"] += len(raw.encode("utf-8", errors="replace"))

        src = {"path": ACTIVE_PATH, "inode": ck["active"]["inode"], "offset": new_offset}
        now_year = datetime.datetime.now().year
        event, dlq = parse_fortigate_line(raw, now_year)
        if event is not None:
            _write_event(ck, event, src)
        else:
            reason = dlq.get("reason", "parse_fail") if dlq else "parse_fail"
            _write_dlq(ck, reason, raw, src)

        ck["active"]["offset"] = int(new_offset)
        offset = int(new_offset)

        if time.time() - start >= max_seconds:
            break

def main() -> None:
    _ensure_dirs()
    ck = load_checkpoint()
    mw = MetricsWindow()

    last_metrics = _now_ts()
    last_flush = _now_ts()

    while True:
        process_rotated_files(ck)
        process_active_tail(ck, max_seconds=2)

        now = _now_ts()
        if now - last_flush >= CHECKPOINT_FLUSH_INTERVAL_SEC:
            try:
                save_checkpoint(ck)
            except Exception:
                ck["counters"]["checkpoint_fail_total"] += 1
            last_flush = now

        if now - last_metrics >= METRICS_INTERVAL_SEC:
            metric = mw.build_metrics(ck, now)
            try:
                append_metrics(metric)
            except Exception:
                ck["counters"]["write_fail_total"] += 1
            last_metrics = now

if __name__ == "__main__":
    main()

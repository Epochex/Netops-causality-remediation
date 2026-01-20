import json
import os
import time
from typing import Any, Dict

PARSED_DIR = "/data/fortigate/parsed"
EVENTS_PREFIX = "events"
DLQ_PREFIX = "dlq"
METRICS_PATH = "/data/fortigate/parsed/metrics.jsonl"

def _hour_key(ts_epoch: int) -> str:
    t = time.localtime(ts_epoch)
    return f"{t.tm_year:04d}{t.tm_mon:02d}{t.tm_mday:02d}-{t.tm_hour:02d}"

def _path_for(prefix: str, hour_key: str) -> str:
    return os.path.join(PARSED_DIR, f"{prefix}-{hour_key}.jsonl")

def append_jsonl(prefix: str, ts_epoch: int, obj: Dict[str, Any]) -> None:
    os.makedirs(PARSED_DIR, exist_ok=True)
    hour_key = _hour_key(ts_epoch)
    path = _path_for(prefix, hour_key)
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)

def append_event(ts_epoch: int, event: Dict[str, Any]) -> None:
    append_jsonl(EVENTS_PREFIX, ts_epoch, event)

def append_dlq(ts_epoch: int, dlq: Dict[str, Any]) -> None:
    append_jsonl(DLQ_PREFIX, ts_epoch, dlq)

def append_metrics(metric_obj: Dict[str, Any]) -> None:
    os.makedirs(PARSED_DIR, exist_ok=True)
    line = json.dumps(metric_obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False) + "\n"
    with open(METRICS_PATH, "a", encoding="utf-8") as f:
        f.write(line)

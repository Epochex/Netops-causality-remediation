import json
import os
import time
from typing import Any, Dict

CHECKPOINT_PATH = "/data/fortigate/parsed/checkpoint.json"

def _atomic_write_json(path: str, obj: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def load_checkpoint() -> Dict[str, Any]:
    if not os.path.exists(CHECKPOINT_PATH):
        return {
            "schema_version": 1,
            "active": {"path": "/data/fortigate/fortigate.log", "inode": None, "offset": 0, "last_event_ts_seen": None},
            "completed": [],  # list of {"path":..., "inode":..., "size":..., "mtime":..., "completed_at":...}
            "counters": {
                "lines_in_total": 0,
                "bytes_in_total": 0,
                "events_out_total": 0,
                "dlq_out_total": 0,
                "parse_fail_total": 0,
                "write_fail_total": 0,
                "checkpoint_fail_total": 0
            },
            "updated_at": int(time.time())
        }
    with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_checkpoint(ck: Dict[str, Any]) -> None:
    ck["updated_at"] = int(time.time())
    _atomic_write_json(CHECKPOINT_PATH, ck)

def completed_key(path: str, inode: int, size: int, mtime: int) -> str:
    return f"{path}|{inode}|{size}|{mtime}"

def is_completed(ck: Dict[str, Any], path: str, inode: int, size: int, mtime: int) -> bool:
    key = completed_key(path, inode, size, mtime)
    for item in ck.get("completed", []):
        if item.get("key") == key:
            return True
    return False

def mark_completed(ck: Dict[str, Any], path: str, inode: int, size: int, mtime: int) -> None:
    key = completed_key(path, inode, size, mtime)
    ck.setdefault("completed", []).append({
        "key": key,
        "path": path,
        "inode": inode,
        "size": size,
        "mtime": mtime,
        "completed_at": int(time.time())
    })
    if len(ck["completed"]) > 5000:
        ck["completed"] = ck["completed"][-5000:]

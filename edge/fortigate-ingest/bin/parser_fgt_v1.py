import datetime
import hashlib
import re
from typing import Any, Dict, Optional, Tuple

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<body>.*)$"
)

def _has_binary_garbage(s: str) -> bool:
    if "\x00" in s:
        return True
    bad = sum(1 for ch in s if ord(ch) < 9 or (11 <= ord(ch) < 32))
    return bad > 5

def parse_kv(body: str) -> Dict[str, str]:
    """
    Parse FortiGate kv pairs: key=value or key="value with spaces"
    Supports backslash-escaped quotes inside quoted values.
    """
    out: Dict[str, str] = {}
    i = 0
    n = len(body)

    while i < n:
        while i < n and body[i] == " ":
            i += 1
        if i >= n:
            break

        k_start = i
        while i < n and body[i] not in "= ":
            i += 1
        key = body[k_start:i]
        if not key or i >= n or body[i] != "=":
            break
        i += 1  # skip '='

        if i < n and body[i] == '"':
            i += 1
            v_chars = []
            while i < n:
                ch = body[i]
                if ch == "\\" and i + 1 < n:
                    v_chars.append(body[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                v_chars.append(ch)
                i += 1
            value = "".join(v_chars)
            while i < n and body[i] == " ":
                i += 1
        else:
            v_start = i
            while i < n and body[i] != " ":
                i += 1
            value = body[v_start:i]
            while i < n and body[i] == " ":
                i += 1

        out[key] = value

    return out

def parse_event_ts(
    kv: Dict[str, str],
    default_year: int,
    fallback_mon: int,
    fallback_day: int,
    fallback_time: str
) -> Optional[str]:
    tz = kv.get("tz")
    if tz:
        tz_clean = tz.strip().strip('"')
        if re.fullmatch(r"[+-]\d{4}", tz_clean):
            tz_norm = tz_clean[:3] + ":" + tz_clean[3:]
        else:
            tz_norm = None
    else:
        tz_norm = None

    date_s = kv.get("date")  # YYYY-MM-DD
    time_s = kv.get("time")  # HH:MM:SS
    if date_s and time_s:
        try:
            dt = datetime.datetime.fromisoformat(f"{date_s}T{time_s}")
            if tz_norm:
                sign = 1 if tz_norm[0] == "+" else -1
                hh = int(tz_norm[1:3])
                mm = int(tz_norm[4:6])
                return dt.replace(
                    tzinfo=datetime.timezone(datetime.timedelta(hours=sign * hh, minutes=sign * mm))
                ).isoformat()
            return dt.isoformat()
        except Exception:
            pass

    try:
        hh, mm, ss = [int(x) for x in fallback_time.split(":")]
        dt = datetime.datetime(default_year, fallback_mon, fallback_day, hh, mm, ss)
        if tz_norm:
            sign = 1 if tz_norm[0] == "+" else -1
            h = int(tz_norm[1:3])
            m = int(tz_norm[4:6])
            return dt.replace(
                tzinfo=datetime.timezone(datetime.timedelta(hours=sign * h, minutes=sign * m))
            ).isoformat()
        return dt.isoformat()
    except Exception:
        return None

def stable_event_id(raw_line: str) -> str:
    h = hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()
    return h[:32]

def parse_fortigate_line(raw_line: str, now_year: int) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Return (event, dlq). One of them is None.
    """
    line = raw_line.rstrip("\n")
    if not line:
        return None, {"reason": "empty_line", "raw": raw_line}

    if _has_binary_garbage(line):
        return None, {"reason": "non_text_or_binary", "raw": raw_line}

    m = SYSLOG_RE.match(line)
    if not m:
        return None, {"reason": "syslog_header_parse_fail", "raw": raw_line}

    mon = m.group("mon")
    day = int(m.group("day"))
    tstr = m.group("time")
    host = m.group("host")
    body = m.group("body")

    mon_i = MONTHS.get(mon)
    if not mon_i:
        return None, {"reason": "invalid_month", "raw": raw_line}

    try:
        kv = parse_kv(body)
    except Exception:
        return None, {"reason": "kv_parse_exception", "raw": raw_line}

    event_ts = parse_event_ts(kv, now_year, mon_i, day, tstr)

    event: Dict[str, Any] = {
        "schema_version": 1,
        "event_id": stable_event_id(raw_line),
        "host": host,
        "event_ts": event_ts,
        "type": kv.get("type"),
        "subtype": kv.get("subtype"),
        "level": kv.get("level"),
        "devname": kv.get("devname"),
        "devid": kv.get("devid"),
        "vd": kv.get("vd"),
        "action": kv.get("action"),
        "policyid": _to_int(kv.get("policyid")),
        "proto": _to_int(kv.get("proto")),
        "service": kv.get("service"),
        "srcip": kv.get("srcip"),
        "srcport": _to_int(kv.get("srcport")),
        "srcintf": kv.get("srcintf"),
        "srcintfrole": kv.get("srcintfrole"),
        "dstip": kv.get("dstip"),
        "dstport": _to_int(kv.get("dstport")),
        "dstintf": kv.get("dstintf"),
        "dstintfrole": kv.get("dstintfrole"),
        "sentbyte": _to_int(kv.get("sentbyte")),
        "rcvdbyte": _to_int(kv.get("rcvdbyte")),
        "sentpkt": _to_int(kv.get("sentpkt")),
        "rcvdpkt": _to_int(kv.get("rcvdpkt")),
        "raw": raw_line,
        "parse_status": "ok"
    }

    core_missing = any(event.get(k) is None for k in ["type", "subtype", "action"])
    if core_missing:
        event["parse_status"] = "partial"

    return event, None

def _to_int(x: Optional[str]) -> Optional[int]:
    if x is None:
        return None
    try:
        return int(x)
    except Exception:
        return None

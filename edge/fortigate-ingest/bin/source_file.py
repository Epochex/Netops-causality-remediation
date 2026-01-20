import gzip
import os
import re
import time
from typing import Dict, Generator, List, Optional, Tuple

ACTIVE_PATH = "/data/fortigate/fortigate.log"
DIR = "/data/fortigate"

ROTATED_RE = re.compile(r"^fortigate\.log-(\d{8}-\d{6})(?:\.gz)?$")

def list_rotated_files() -> List[str]:
    files = []
    for name in os.listdir(DIR):
        if ROTATED_RE.match(name):
            files.append(os.path.join(DIR, name))

    def key_fn(p: str) -> str:
        m = ROTATED_RE.match(os.path.basename(p))
        return m.group(1) if m else "99999999-999999"

    files.sort(key=key_fn)
    return files

def stat_file(path: str) -> Tuple[int, int, int]:
    st = os.stat(path)
    return (st.st_ino, st.st_size, int(st.st_mtime))

def read_whole_file_lines(path: str) -> Generator[Tuple[str, Dict], None, None]:
    """
    Yield (line, source_pos) for rotated immutable files.
    source_pos includes path, inode, offset (byte offset in file for plain files; for gz, offset is None).
    """
    inode, size, mtime = stat_file(path)
    is_gz = path.endswith(".gz")
    if is_gz:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line, {"path": path, "inode": inode, "offset": None, "size": size, "mtime": mtime}
    else:
        offset = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line, {"path": path, "inode": inode, "offset": offset, "size": size, "mtime": mtime}
                offset += len(line.encode("utf-8", errors="replace"))

def follow_active_binary(offset: int) -> Generator[Tuple[str, int], None, None]:
    """
    Follow file using binary mode for correct byte offsets.
    Yield decoded line (utf-8 replace) and updated byte offset.
    """
    with open(ACTIVE_PATH, "rb") as f:
        f.seek(offset, os.SEEK_SET)
        buf = b""
        while True:
            chunk = f.read(8192)
            if not chunk:
                time.sleep(0.2)
                continue
            buf += chunk
            while True:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                line_bytes = buf[:nl + 1]
                buf = buf[nl + 1:]
                offset += len(line_bytes)
                line = line_bytes.decode("utf-8", errors="replace")
                yield line, offset

def active_inode() -> Optional[int]:
    try:
        return os.stat(ACTIVE_PATH).st_ino
    except FileNotFoundError:
        return None

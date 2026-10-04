"""src/pipeline/loader.py
Safe Log File Loader for Rox Platform
Reads uploaded file objects or disk paths, enforces size limits, and yields decoded lines.
"""

from pathlib import Path
from typing import Union, List, Tuple, Optional
import io

# Maximum upload limit: 350 MB to comfortably support full enterprise honeypot datasets (e.g. 215 MB cj.log)
MAX_FILE_SIZE_BYTES = 350 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}


class LogLoader:
    """Safe loader for web access log files."""

    @staticmethod
    def load_bytes_or_file(
        source: Union[bytes, io.BytesIO, Path, str],
        filename: str = "",
        max_rows: Optional[int] = None,
    ) -> Tuple[List[str], str, float, str]:
        """Loads lines from file source with automatic encoding detection, safety checks, and optional row cap.
        
        Returns:
            Tuple of (raw_lines, filename, size_kb, error_message)
        """
        raw_bytes = b""
        name = filename or "uploaded_log"

        if isinstance(source, (str, Path)):
            p = Path(source)
            name = p.name
            if not p.exists():
                return [], name, 0.0, f"File does not exist: {p.name}"
            size = p.stat().st_size
            if size > MAX_FILE_SIZE_BYTES:
                return [], name, size / 1024, f"File exceeds safe limit of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."
            with open(p, "rb") as f:
                raw_bytes = f.read()
        elif hasattr(source, "getvalue"):
            raw_bytes = source.getvalue()
        elif hasattr(source, "read"):
            raw_bytes = source.read()
            if hasattr(source, "seek"):
                source.seek(0)
        elif isinstance(source, (bytes, bytearray)):
            raw_bytes = bytes(source)

        size_kb = len(raw_bytes) / 1024.0

        if not raw_bytes:
            return [], name, 0.0, "The provided log file is empty."

        ext = Path(name).suffix.lower()
        if ext and ext not in SUPPORTED_EXTENSIONS:
            return [], name, size_kb, f"Unsupported file extension '{ext}'. Rox supports: {', '.join(sorted(SUPPORTED_EXTENSIONS))}."

        # Decoding with progressive fallbacks
        decoded_text = ""
        for encoding in ["utf-8", "latin-1", "cp1252", "ascii"]:
            try:
                decoded_text = raw_bytes.decode(encoding)
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if not decoded_text:
            decoded_text = raw_bytes.decode("utf-8", errors="replace")

        lines: List[str] = []
        for line in decoded_text.splitlines():
            s = line.strip()
            if s:
                lines.append(s)
                if max_rows is not None and len(lines) >= max_rows:
                    break

        return lines, name, round(size_kb, 2), ""

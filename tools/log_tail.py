from collections import deque

from security import validate_log_path

_MAX_FILE_BYTES = 20 * 1024 * 1024  # 20 MB
_MAX_GREP_LEN = 100


async def tail_log(args: dict) -> dict:
    path = args.get("path", "").strip()
    if not path:
        return {"error": "Parameter 'path' is required"}

    lines = min(int(args.get("lines", 50)), 500)
    grep_filter = args.get("grep", "")

    if len(grep_filter) > _MAX_GREP_LEN:
        raise ValueError(f"grep pattern too long (max {_MAX_GREP_LEN} chars)")

    resolved = validate_log_path(path)

    try:
        file_size = resolved.stat().st_size
        if file_size > _MAX_FILE_BYTES:
            raise PermissionError(f"File too large ({file_size} bytes, max {_MAX_FILE_BYTES})")

        result_lines: deque[str] = deque(maxlen=lines)
        with open(resolved, "r", errors="replace") as f:
            for line in f:
                stripped = line.rstrip()
                if not grep_filter or grep_filter in stripped:
                    result_lines.append(stripped)
    except OSError as e:
        return {"error": f"File read error: {e}"}

    return {
        "path": path,
        "lines_returned": len(result_lines),
        "lines_requested": lines,
        "grep": grep_filter or None,
        "content": list(result_lines),
    }

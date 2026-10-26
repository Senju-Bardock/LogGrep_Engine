#!/usr/bin/env python3
"""Self-test for LogGrep: checks that the C engine gives exactly the same
results as the Python engine.

It builds a log full of awkward lines (quotes, commas, control characters,
Unicode and invalid UTF-8), runs both engines with several options and
compares the console output, the summaries and the exported files byte by byte.

Usage (log_searcher must be built first):
    python selftest.py
"""

import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import loggrep  # noqa: E402  (used only to locate the C binary)

LOGGREP = HERE / "loggrep.py"

QUERIES = {
    "levels": {
        "CRITICAL": ["CRITICAL", "FATAL"],
        "ERROR": ["ERROR"],
        "WARN": ["WARN", "WARNING"],
        "INFO": ["INFO"],
        "DEBUG": ["DEBUG", "TRACE"],
    },
    "profiles": {
        "t": {"patterns": ["TESTLINE"], "exclude": ["EXCLUDEME"], "severity": "AUDIT"},
    },
}

FIXED_LINES = [
    b"TESTLINE plain ERROR message",
    b"TESTLINE [WARNING] something",
    b"TESTLINE FATAL boom and ERROR too",
    b"TESTLINE ERRORS is not a level, nor is FATALITY or foo_ERROR",
    b"TESTLINE lowercase error is not a level",
    b'TESTLINE quotes " and commas , and \\ backslash',
    b"TESTLINE tab\there, bell\x07, nul\x00, esc\x1b, del\x7f, ff\x0c, vt\x0b, bs\x08",
    b"TESTLINE carriage\rreturn in the middle",
    b"TESTLINE trailing carriage returns\r\r",
    "TESTLINE unicode: caf\u00e9 \u65e5\u672c\u8a9e \U0001F600 line\u2028separator".encode("utf-8"),
    b"TESTLINE lone continuation \x80 and \xbf",
    b"TESTLINE truncated \xe2\x82 then text",
    b"TESTLINE truncated 4-byte \xf0\x9f\x98 then text",
    b"TESTLINE overlong \xc0\x80 and \xe0\x80\x80",
    b"TESTLINE surrogate \xed\xa0\x80 and too big \xf4\x90\x80\x80",
    b"TESTLINE invalid leads \xff\xfe\xf8",
    b"TESTLINE EXCLUDEME this one is excluded",
    b"TESTLINE INFO at the end without a newline \xe2\x82",
]


def build_log(path):
    rnd = random.Random(1234)
    alphabet = (
        [b"a", b"b", b" ", b",", b'"', b"\\", b"\r", b"\t"]
        + [bytes([b]) for b in range(0x80, 0x100)] * 2
        + [bytes([b]) for b in range(0x00, 0x20) if b not in (0x0A,)]
        + ["\u00e9".encode(), "\u65e5".encode(), "\U0001F600".encode()] * 4
    )
    lines = list(FIXED_LINES[:-1])
    for _ in range(4000):
        body = b"".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
        lines.append(b"TESTLINE " + body)
    lines.append(b"NOMATCH here")
    with open(path, "wb") as f:
        for i, line in enumerate(lines):
            f.write(line + (b"\r\n" if i % 7 == 0 else b"\n"))
        f.write(FIXED_LINES[-1])  # last line has no newline


def run(engine, log, queries, extra, export=None):
    cmd = [sys.executable, str(LOGGREP), str(log), "-q", str(queries), "--engine", engine, "--no-color"] + extra
    if export:
        cmd += ["--export", str(export)]
    proc = subprocess.run(cmd, capture_output=True)
    wanted = ("Lines scanned", "Matches", "By level")
    summary = [l for l in proc.stderr.decode("utf-8", "replace").splitlines() if l.startswith(wanted)]
    # tie order between levels with equal counts may differ: compare as sets
    summary = [" ".join(sorted(l.replace(",", " ").split())) for l in summary]
    return proc.stdout, summary, proc.returncode


def main():
    if not loggrep.find_c_binary():
        sys.exit("log_searcher not found. Build it first: "
                 "gcc -O2 -Wall -Wextra -o log_searcher log_searcher.c")
    failures = 0
    checks = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        log, queries = tmp / "awkward.log", tmp / "queries.json"
        build_log(log)
        queries.write_text(json.dumps(QUERIES), encoding="utf-8")

        cases = {
            "no profile": ["-e", "TESTLINE"],
            "profile with severity fallback": ["-p", "t"],
            "ignore case": ["-e", "testline", "-i"],
            "exclude": ["-e", "TESTLINE", "-x", "EXCLUDEME"],
            "max matches": ["-e", "TESTLINE", "-m", "50"],
            "no matches": ["-e", "THIS_NEVER_APPEARS"],
        }
        for name, extra in cases.items():
            # console output and summary (line mode, then count-only mode)
            for mode, flags in (("lines", []), ("count", ["--count"])):
                py = run("python", log, queries, extra + flags)
                c = run("c", log, queries, extra + flags)
                checks += 1
                if py != c:
                    failures += 1
                    print(f"FAIL  {name} [{mode}]: console output or summary differ")
            # exported files, byte by byte
            for kind in ("txt", "csv", "json"):
                out_py, out_c = tmp / f"py.{kind}", tmp / f"c.{kind}"
                run("python", log, queries, extra + ["--count"], out_py)
                run("c", log, queries, extra + ["--count"], out_c)
                checks += 1
                a, b = out_py.read_bytes(), out_c.read_bytes()
                if a != b:
                    failures += 1
                    print(f"FAIL  {name} [export .{kind}]: files differ ({len(a)} vs {len(b)} bytes)")
                elif kind == "json":
                    json.loads(a.decode("utf-8"))  # must also be valid JSON
        print(f"{checks - failures}/{checks} checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

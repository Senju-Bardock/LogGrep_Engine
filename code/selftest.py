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
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import warnings
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


def check_chunk_boundaries(tmp, log):
    """Builds log_searcher with a tiny mapping chunk (64 bytes) and compares it
    with the buffered reader: this exercises every chunk-boundary case of the
    memory-mapped scan on a small file. Returns (checks, failures)."""
    compiler = shutil.which("gcc") or shutil.which("cc")
    source = HERE / "log_searcher.c"
    if not compiler or not source.exists():
        print("skip  chunk-boundary check (needs gcc and log_searcher.c next to this script)")
        return 0, 0
    tiny = tmp / ("tiny.exe" if os.name == "nt" else "tiny")
    flags = ["-O2", "-DMAP_CHUNK=64", "-DPAR_MIN_BYTES=0"] + ([] if os.name == "nt" else ["-pthread"])
    build = subprocess.run([compiler] + flags + ["-o", str(tiny), str(source)], capture_output=True)
    if build.returncode != 0:
        print("skip  chunk-boundary check (could not compile the test build)")
        return 0, 0
    levels = ["-l", "CRITICAL=CRITICAL,FATAL", "-l", "ERROR=ERROR", "-l", "WARN=WARN,WARNING"]
    searches = [
        ["-e", "TESTLINE"], ["-e", "ERROR", "-e", "WARN"], ["-e", "a", "-e", "b"], ["-e", "TESTLINE", "-i"],
        ["-e", "TESTLINE", "-x", "EXCLUDEME"], ["-e", "TESTLINE", "-m", "37"], ["-e", "THIS_NEVER_APPEARS"],
    ]
    checks = failures = 0
    for extra in searches:
        for flags in ([], ["-c"]):
            cmd = extra + levels + flags + [str(log)]
            a = subprocess.run([str(tiny), "-j", "1"] + cmd, capture_output=True)
            b = subprocess.run([str(tiny), "-B"] + cmd, capture_output=True)
            checks += 1
            if (a.stdout, a.stderr, a.returncode) != (b.stdout, b.stderr, b.returncode):
                failures += 1
                print(f"FAIL  chunk boundaries: {' '.join(extra + flags)}")
            for threads in ("2", "5"):  # the same search split between several threads
                t = subprocess.run([str(tiny), "-j", threads] + cmd, capture_output=True)
                checks += 1
                if (t.stdout, t.stderr, t.returncode) != (b.stdout, b.stderr, b.returncode):
                    failures += 1
                    print(f"FAIL  {threads} threads give a different result: {' '.join(extra + flags)}")
    return checks, failures


WORDS = ["Failed", "password", "ERROR", "warn", "abc", "user", "Invalid", "KeyError", "ab", "x1"]


def random_regex(rnd):
    """A random regular expression made of the constructs the C engine supports
    (plus a few it does not, which must be refused rather than mis-handled)."""
    def atom(depth):
        k = rnd.random()
        if k < 0.20:
            return rnd.choice(WORDS)  # fixed text: the C engine searches for it before running the regex
        if k < 0.35:
            return rnd.choice(list("abAB01_x"))
        if k < 0.43:
            return "."
        if k < 0.58:
            body = "".join(rnd.choice(["a", "b", "0-9", "A-C", r"\d", r"\w", r"\s", "_", " ", r"\."]) for _ in range(rnd.randint(1, 3)))
            return "[" + ("^" if rnd.random() < 0.3 else "") + body + "]"
        if k < 0.68:
            return rnd.choice([r"\d", r"\w", r"\s", r"\D", r"\W", r"\S", r"\."])
        if k < 0.78:
            return rnd.choice([r"\b", "^", "$", r"\B"])
        if depth > 0:
            return rnd.choice(["(", "(?:", "(?P<g>"]) + alt(depth - 1) + ")"
        return "a"

    def concat(depth):
        out = ""
        for _ in range(rnd.randint(1, 4)):
            out += atom(depth) + rnd.choice(["", "", "", "*", "+", "?", "{2}", "{1,3}", "{,2}", "{2,}", "*?", "+?"])
        return out

    def alt(depth):
        return "|".join(concat(depth) for _ in range(rnd.choice([1, 1, 2, 3])))

    return alt(rnd.choice([0, 1, 2]))


def check_regex_differential(tmp, count=300):
    """Compares the C regex engine with Python's re on random expressions and
    random lines, and checks that the fixed strings it searches for first
    (printed by -k) really occur in every line the expression matches.
    Expressions the C engine refuses (exit code 3) are skipped.
    Returns (checks, failures)."""
    binary = loggrep.find_c_binary()
    rnd = random.Random(99)
    path = tmp / "regex_lines.log"
    checks = failures = 0
    warnings.simplefilter("ignore")
    for _ in range(count):
        pattern, icase = random_regex(rnd), rnd.random() < 0.3
        lines = []
        for _ in range(rnd.randint(1, 40)):
            pieces = list("abAB01_ -.,x") + WORDS + [" "]
            text = "".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 8)))
            lines.append(text.encode() + (b"\r" if rnd.random() < 0.1 else b""))
        try:
            compiled = re.compile(pattern.encode(), re.IGNORECASE if icase else 0)
        except re.error:
            continue
        path.write_bytes(b"".join(line + b"\n" for line in lines))
        flags = ["-i"] if icase else []
        proc = subprocess.run([binary] + flags + ["-r", pattern, str(path)], capture_output=True)
        if proc.returncode == 3:
            continue
        checks += 1
        got = {int(row.split(b"|", 1)[0]) for row in proc.stdout.split(b"\n") if row}
        want = {i for i, line in enumerate(lines, 1) if compiled.search(line.rstrip(b"\r\n"))}
        if got != want:
            failures += 1
            print(f"FAIL  regex differs from Python's re: {pattern!r}{' (ignore case)' if icase else ''}")
        probe = subprocess.run([binary, "-k"] + flags + ["-r", pattern], capture_output=True)
        required = [bytes.fromhex(row.split()[1]) for row in probe.stderr.decode().splitlines() if row.startswith("#prefilter ")]
        if required:
            checks += 1
            for i in want:
                text = lines[i - 1].rstrip(b"\r\n")
                text = text.lower() if icase else text
                if not any(item in text for item in required):
                    failures += 1
                    print(f"FAIL  searched strings {required} missing from a line matched by {pattern!r}")
                    break
    return checks, failures


PREFILTER_CASES = [
    "Failed password|Invalid user", "(?:Failed )?password", "Fail(ed)?", "(?:abc)?def", "ab{0,2}cde",
    "(?:abc){0,2}xyz", "(?:abc)*xyz", "(abc|)def", "abc+d", "(?:abc){1,2}d", "a(bc)?d", "KeyError|Key",
    "(KeyError|ERROR)?x1", "(?:^|[ ])ERROR(?: |$)", "Fail.*password", "pass(word)?[0-9]*", "[Ww]arn|WARN",
    "unau?thori[sz]ed", "(?:ab|cd){2}ef", "x{0}abc", "(abc){,2}d", "^(?:ERROR|WARN)x1$",
    "Failed|[0-9]+", "ERROR|a.c|zzz", "(?:Fail|\\w+)ed", "abc|^$", "(?:Failed|)password",
]


def check_prefilter_cases(tmp):
    """Hand-picked expressions where the fixed text that must be present is easy
    to get wrong (optional parts, {0,n} repeats, empty alternatives...). For each
    one, compares the C engine with Python's re and checks that the strings it
    searches for first occur in every matching line. Returns (checks, failures)."""
    binary = loggrep.find_c_binary()
    rnd = random.Random(7)
    pieces = ["Failed password", "password", "Fail", "Failed", "abc", "abcdef", "def", "xyz", "abcabcxyz", "abbcde",
              "acde", "abcde", "abcd", "KeyError", "Key", "ERROR x1", "x1", "ERROR", "WARN", "warn", "Warn",
              "unathorized", "unauthorized", "unauthorised", "Invalid user", "pass", "pass12", "ab", "cdcdef", " ", ""]
    lines = [piece.encode() for piece in pieces]
    lines += [b"".join(rnd.choice(pieces).encode() + rnd.choice([b"", b" "]) for _ in range(rnd.randint(1, 4))) for _ in range(150)]
    path = tmp / "prefilter_cases.log"
    path.write_bytes(b"".join(line + b"\n" for line in lines))
    checks = failures = 0
    for pattern in PREFILTER_CASES:
        for icase in (False, True):
            flags = ["-i"] if icase else []
            compiled = re.compile(pattern.encode(), re.IGNORECASE if icase else 0)
            want = {i for i, line in enumerate(lines, 1) if compiled.search(line)}
            proc = subprocess.run([binary] + flags + ["-r", pattern, str(path)], capture_output=True)
            checks += 1
            if proc.returncode == 3:
                failures += 1
                print(f"FAIL  {pattern!r} is refused by the C engine")
                continue
            got = {int(row.split(b"|", 1)[0]) for row in proc.stdout.split(b"\n") if row}
            if got != want:
                failures += 1
                print(f"FAIL  {pattern!r}{' (ignore case)' if icase else ''}: different lines than Python's re")
            probe = subprocess.run([binary, "-k"] + flags + ["-r", pattern], capture_output=True)
            required = [bytes.fromhex(row.split()[1]) for row in probe.stderr.decode().splitlines() if row.startswith("#prefilter ")]
            checks += 1
            for i in want:
                text = lines[i - 1].lower() if icase else lines[i - 1]
                if required and not any(item in text for item in required):
                    failures += 1
                    print(f"FAIL  {pattern!r}: searched strings {required} missing from a matching line")
                    break
    return checks, failures


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
            "regex alternation": ["-r", "ERROR|WARN"],
            "regex anchors and word boundary": ["-r", r"^TESTLINE .*\bERROR\b"],
            "regex end anchor (CRLF lines)": ["-r", "message$"],
            "regex classes and counts": ["-r", r"[0-9]{1,3}\.[A-Za-z]+", "-r", "ab{2,}c?"],
            "regex ignore case": ["-r", "testline [a-z]+ error", "-i"],
            "regex and literal together": ["-e", "boom", "-r", r"\bINFO\b", "-x", "EXCLUDEME"],
            "regex with severity fallback": ["-p", "t", "-r", "lowercase|plain"],
        }
        for name, extra in cases.items():
            # console output and summary (line mode, then count-only mode)
            for mode, flags in (("lines", []), ("count", ["--count"])):
                py = run("python", log, queries, extra + flags)
                c = run("c", log, queries, extra + flags)
                c_blocks = run("c", log, queries, extra + flags + ["--no-mmap"])
                c_threads = run("c", log, queries, extra + flags + ["--threads", "3"])
                checks += 1
                if py != c or py != c_blocks or py != c_threads:
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
        # an expression the C engine cannot handle must silently run in Python
        for flags in ([], ["--count"]):
            fallback = ["-r", r"(?<=TESTLINE )plain", "-r", r"(\w)\1"]
            checks += 1
            if run("auto", log, queries, fallback + flags) != run("python", log, queries, fallback + flags):
                failures += 1
                print("FAIL  unsupported regex: automatic fallback to Python gives different results")
        extra_checks, extra_failures = check_chunk_boundaries(tmp, log)
        checks += extra_checks
        failures += extra_failures
        extra_checks, extra_failures = check_prefilter_cases(tmp)
        checks += extra_checks
        failures += extra_failures
        extra_checks, extra_failures = check_regex_differential(tmp)
        checks += extra_checks
        failures += extra_failures
        print(f"{checks - failures}/{checks} checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

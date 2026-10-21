#!/usr/bin/env python3
"""loggrep - Log searcher with JSON profiles (pure Python version).

Quick usage:
    python loggrep.py app.log -p errors
    python loggrep.py app.log -e "Timeout" -e "Failed password" -i
    python loggrep.py app.log -p security_audit --export report.csv
    python loggrep.py app.log -p security_audit --engine c
    python loggrep.py --list-profiles

Uses only the standard library. The search engine is a swappable function
(see ENGINES). The C engine (log_searcher) is used automatically when its
binary is next to this script or in the PATH and the search is literal-only;
regular expressions always run in the Python engine.
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

DEFAULT_QUERIES = Path(__file__).with_name("queries.json")

# --- ANSI colors ------------------------------------------------------------
RESET = "\033[0m"
HIGHLIGHT = "\033[1;7m"  # bold + inverse video for the matched text
LEVEL_COLORS = {
    "CRITICAL": "\033[1;31m",
    "ERROR": "\033[31m",
    "WARN": "\033[33m",
    "INFO": "\033[32m",
    "DEBUG": "\033[36m",
}


# --- Configuration ----------------------------------------------------------
def load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Error: profiles file '{path}' not found.")
    except json.JSONDecodeError as e:
        sys.exit(f"Error: '{path}' is not valid JSON (line {e.lineno}, column {e.colno}): {e.msg}")
    if not isinstance(config.get("profiles", {}), dict):
        sys.exit("Error: 'profiles' must be an object in queries.json.")
    return config


def build_level_regexes(config):
    """One regex (over bytes) per level, in the order they appear in the JSON."""
    levels = config.get("levels", {})
    result = []
    for name, words in levels.items():
        expr = r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b"
        result.append((name, re.compile(expr.encode("utf-8"))))
    return result


def classify(line, level_regexes):
    for name, rx in level_regexes:
        if rx.search(line):
            return name
    return None


# --- Matcher ----------------------------------------------------------------
class Matcher:
    """Combines literal patterns and regexes into a single compiled regex."""

    def __init__(self, literals, regexes, excludes, ignore_case):
        self.literals = literals
        self.regexes = regexes
        self.excludes = excludes
        self.ignore_case = ignore_case
        flags = re.IGNORECASE if ignore_case else 0
        parts = [re.escape(p) for p in literals] + [f"(?:{r})" for r in regexes]
        expr = "|".join(parts)
        try:
            self.include_str = re.compile(expr, flags)
            self.include_bytes = re.compile(expr.encode("utf-8"), flags)
        except re.error as e:
            sys.exit(f"Error in regular expression: {e}")
        if excludes:
            exc = "|".join(re.escape(x) for x in excludes)
            self.exclude_bytes = re.compile(exc.encode("utf-8"), flags)
        else:
            self.exclude_bytes = None


# --- Search engines ---------------------------------------------------------
class Stats:
    def __init__(self):
        self.lines = 0
        self.bytes = 0
        self.matches = 0
        self.levels = Counter()


def search_python(path, matcher, stats, max_matches=0):
    """Yields (line_number, line_bytes) for every match.

    Reads in binary mode and only decodes the lines that match, so it is
    faster than working with text and never fails on odd encodings.
    """
    include = matcher.include_bytes.search
    exclude = matcher.exclude_bytes.search if matcher.exclude_bytes else None
    n = 0
    with open(path, "rb") as f:
        try:
            for n, line in enumerate(f, 1):
                if include(line) and not (exclude and exclude(line)):
                    yield n, line.rstrip(b"\r\n")
        finally:
            stats.lines = n
            stats.bytes = f.tell()  # bytes actually read (useful with --max)


C_MAX_PATTERNS = 64  # limit compiled into log_searcher.c
STATS_RE = re.compile(rb"#stats lines=(\d+) bytes=(\d+) matches=(\d+)")


def find_c_binary():
    """Looks for log_searcher next to this script, then in the PATH."""
    names = ["log_searcher.exe", "log_searcher"] if os.name == "nt" else ["log_searcher"]
    here = Path(__file__).resolve().parent
    for name in names:
        candidate = here / name
        if candidate.is_file():
            return str(candidate)
    return shutil.which("log_searcher")


def c_unsupported_reason(matcher):
    """Returns why the C engine cannot run this search, or None if it can."""
    if matcher.regexes:
        return "the C engine only supports literal patterns, not regular expressions"
    if len(matcher.literals) > C_MAX_PATTERNS or len(matcher.excludes) > C_MAX_PATTERNS:
        return f"the C engine accepts at most {C_MAX_PATTERNS} patterns of each kind"
    if not all(t.isascii() for t in matcher.literals + matcher.excludes):
        return "the C engine only supports ASCII patterns"
    return None


def search_c(path, matcher, stats, max_matches=0):
    """Runs log_searcher and yields (line_number, line_bytes) from its stdout.

    The binary prints one 'number|content' line per match and a final
    '#stats lines=N bytes=N matches=N' line on stderr.
    """
    binary = find_c_binary()
    if not binary:
        sys.exit("Error: log_searcher not found. Build it with: "
                 "gcc -O2 -Wall -Wextra -o log_searcher log_searcher.c")
    cmd = [binary]
    if matcher.ignore_case:
        cmd.append("-i")
    if max_matches:
        cmd += ["-m", str(max_matches)]
    for text in matcher.literals:
        cmd += ["-e", text]
    for text in matcher.excludes:
        cmd += ["-x", text]
    cmd.append(str(path))

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1 << 20)
    try:
        for raw in proc.stdout:
            sep = raw.index(b"|")
            yield int(raw[:sep]), raw[sep + 1:].rstrip(b"\n")
    finally:
        # If the consumer stopped early, the process may still be running.
        if proc.poll() is None:
            proc.terminate()
        proc.stdout.close()
        err = proc.stderr.read()
        proc.stderr.close()
        code = proc.wait()
        found = STATS_RE.search(err)
        if found:
            stats.lines, stats.bytes = int(found.group(1)), int(found.group(2))
        if code == 2:
            sys.exit("Error from log_searcher: " + err.decode("utf-8", errors="replace").strip())


ENGINES = {"python": search_python, "c": search_c}


def select_engine(requested, matcher):
    """Resolves --engine (auto/python/c) into the name of the engine to run."""
    if requested == "python":
        return "python"
    reason = c_unsupported_reason(matcher)
    if requested == "c":
        if reason:
            sys.exit(f"Error: cannot use --engine c: {reason}.")
        if not find_c_binary():
            sys.exit("Error: log_searcher not found. Build it with: "
                     "gcc -O2 -Wall -Wextra -o log_searcher log_searcher.c")
        return "c"
    return "c" if reason is None and find_c_binary() else "python"


# --- Output -----------------------------------------------------------------
def highlight(text, rx, base):
    out, last = [], 0
    for m in rx.finditer(text):
        if m.end() == m.start():
            continue
        out.append(text[last:m.start()])
        out.append(f"{HIGHLIGHT}{m.group()}{RESET}{base}")
        last = m.end()
    out.append(text[last:])
    return "".join(out)


def format_line(n, text, level, rx, use_color):
    if not use_color:
        tag = f"[{level}] " if level else ""
        return f"{n:>9} | {tag}{text}"
    base = LEVEL_COLORS.get(level, "")
    tag = f"[{level}] " if level else ""
    return f"\033[2m{n:>9} |{RESET} {base}{tag}{highlight(text, rx, base)}{RESET}"


class Exporter:
    """Streams matches to a .txt, .csv or .json file."""

    def __init__(self, path):
        self.kind = Path(path).suffix.lower().lstrip(".")
        if self.kind not in ("txt", "csv", "json"):
            sys.exit("Error: --export must end in .txt, .csv or .json")
        self.f = open(path, "w", encoding="utf-8", newline="")
        self.first = True
        if self.kind == "csv":
            self.writer = csv.writer(self.f)
            self.writer.writerow(["line", "level", "text"])
        elif self.kind == "json":
            self.f.write("[\n")

    def write(self, n, level, text):
        if self.kind == "txt":
            self.f.write(f"{n}:{level or '-'}|{text}\n")
        elif self.kind == "csv":
            self.writer.writerow([n, level or "", text])
        else:
            if not self.first:
                self.f.write(",\n")
            self.f.write("  " + json.dumps({"line": n, "level": level, "text": text}, ensure_ascii=False))
            self.first = False

    def close(self):
        if self.kind == "json":
            self.f.write("\n]\n")
        self.f.close()


def print_stats(stats, elapsed, engine):
    mb = stats.bytes / 1_000_000
    rate_mb = mb / elapsed if elapsed > 0 else 0
    rate_lines = stats.lines / elapsed if elapsed > 0 else 0
    print("\n--- Summary ---", file=sys.stderr)
    print(f"Lines scanned : {stats.lines:,}", file=sys.stderr)
    print(f"Matches       : {stats.matches:,}", file=sys.stderr)
    if stats.levels:
        detail = ", ".join(f"{k}={v:,}" for k, v in stats.levels.most_common())
        print(f"By level      : {detail}", file=sys.stderr)
    print(f"Time          : {elapsed:.2f} s", file=sys.stderr)
    print(f"Speed         : {rate_mb:,.1f} MB/s ({rate_lines:,.0f} lines/s)", file=sys.stderr)
    print(f"Engine        : {engine}", file=sys.stderr)


# --- CLI --------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Log searcher with JSON profiles.")
    p.add_argument("file", nargs="?", help="log file to analyze")
    p.add_argument("-p", "--profile", help="profile name in queries.json")
    p.add_argument("-q", "--queries", default=str(DEFAULT_QUERIES), help="path to the profiles JSON")
    p.add_argument("-e", "--pattern", action="append", default=[], help="literal text to search for (repeatable)")
    p.add_argument("-r", "--regex", action="append", default=[], help="regular expression (repeatable)")
    p.add_argument("-x", "--exclude", action="append", default=[], help="exclude lines containing this text (repeatable)")
    p.add_argument("-i", "--ignore-case", action="store_true", help="case-insensitive matching")
    p.add_argument("-m", "--max", type=int, default=0, help="stop after N matches")
    p.add_argument("--count", action="store_true", help="do not print lines, only the summary")
    p.add_argument("--export", metavar="FILE", help="export matches (.txt, .csv or .json)")
    p.add_argument("--no-color", action="store_true", help="disable colors")
    p.add_argument("--engine", choices=["auto", "python", "c"], default="auto",
                   help="search engine: auto uses C when available and possible (default)")
    p.add_argument("--list-profiles", action="store_true", help="list available profiles and exit")
    return p.parse_args()


def setup_console():
    # Make the Windows cmd interpret ANSI codes and display UTF-8.
    os.system("")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass


def main():
    setup_console()
    args = parse_args()
    config = load_config(args.queries)
    profiles = config.get("profiles", {})

    if args.list_profiles:
        for name, prof in profiles.items():
            print(f"{name:<16} {prof.get('description', '')}")
        return

    if not args.file:
        sys.exit("Error: specify the log file. Example: python loggrep.py app.log -p errors")
    if not os.path.isfile(args.file):
        sys.exit(f"Error: file '{args.file}' not found.")

    literals, regexes, excludes = list(args.pattern), list(args.regex), list(args.exclude)
    severity, ignore_case = None, args.ignore_case
    if args.profile:
        prof = profiles.get(args.profile)
        if prof is None:
            sys.exit(f"Error: profile '{args.profile}' does not exist. Available: {', '.join(profiles) or '(none)'}")
        literals += prof.get("patterns", [])
        regexes += prof.get("regex", []) if isinstance(prof.get("regex", []), list) else [prof["regex"]]
        excludes += prof.get("exclude", [])
        severity = prof.get("severity")
        ignore_case = ignore_case or prof.get("ignore_case", False)

    if not literals and not regexes:
        sys.exit("Error: specify a profile (-p) or at least one pattern (-e) or regex (-r).")

    matcher = Matcher(literals, regexes, excludes, ignore_case)
    level_regexes = build_level_regexes(config)
    use_color = not args.no_color and sys.stdout.isatty()
    exporter = Exporter(args.export) if args.export else None
    stats = Stats()
    engine_name = select_engine(args.engine, matcher)

    start = time.perf_counter()
    results = ENGINES[engine_name](args.file, matcher, stats, args.max)
    try:
        for n, raw in results:
            stats.matches += 1
            level = classify(raw, level_regexes) or severity
            stats.levels[level or "NO_LEVEL"] += 1
            text = raw.decode("utf-8", errors="replace")
            if exporter:
                exporter.write(n, level, text)
            if not args.count:
                print(format_line(n, text, level, matcher.include_str, use_color))
            if args.max and stats.matches >= args.max:
                results.close()
                break
    except BrokenPipeError:
        # For example: python loggrep.py app.log -p errors | more
        sys.stderr.close()
        return
    finally:
        if exporter:
            exporter.close()
    print_stats(stats, time.perf_counter() - start, engine_name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

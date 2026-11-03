# LogGrep_Engine
## Work in progress
A command-line utility designed to search for patterns, regular expressions, and anomalies in massive log files (gigabytes of text), utilizing a high-speed search engine written in C, wrapped in a user-friendly Python CLI, and managed via JSON-based search profiles.

## Technical Architecture:

-- Search Engine in C (log_searcher.c): Implements efficient substring-matching algorithms (such as Boyer-Moore or finite automata) and utilizes memory-mapped file I/O (mmap) to scan millions of lines per second without exhausting RAM.

-- Python Interface and Wrapper (loggrep.py): Captures user parameters from the terminal, invokes the C binary or library, formats the results with syntax highlighting, and exports match reports.

-- Profile Management via JSON (queries.json): Enables the storage of complex filter sets, frequently used regular expressions, and categorization rules (e.g., automatically classifying critical errors as ERROR, warnings as WARN, and debug events as DEBUG).

## Progress log:

### 20/10/2026

- made pure python code to do tests
- done queries.json
- made python log_gen. Generates 1 million logs in test.log

-- Comments: With resource-intensive regex patterns—such as those for IP addresses—performance drops to around 15 MB/s. My own system may yield different figures, but I will make a note of them; they set the benchmark that the C-based engine will need to surpass. Look in notes folder

### 21/10/2026

- made log_search.c
- tested the code and did gcc
- integrated c in loggrep code
- some bugs have been fixed and got even way faster

-- Comments: There is 2 bottlenecks I'm trying to solve, from now on, mmap will be put on the side and for some days I'll be investigating how can I solve this and make this even faster. Maybe I will have to do a new python code just to check anyways. For now, I seem to make a solution for the first bottleneck that stresses me, but it is not solved yet.

### 26/10/2026

- made `selftest.py`
- tested code and solve 2 bottlenecks
- Now it is between 6-7 times faster, and the export is already nearly at the level of C alone (0.18 s). Using `--export` without `--count` also results in a speedup, though to a lesser extent, because Python still prints every line.
- A previous issue that surfaced during testing: for lines ending in \r\r\n, the behavior in Python and C did not match, because the C implementation removed only a single \r, whereas Python removes all of them. This has now been reconciled.
- If the log or export path contains non-ASCII characters (for example, `informé.csv`), the C component is bypassed for that part and Python handles it instead, because Windows loses those characters when passing them to the program. The result remains correct, though the process is slower.
- `log_searcher` includes three new options, in case you use it manually: `-o FILE`, `-F txt|csv|json`, and `-s LEVEL`.

-- Comments: The files turn out identical to those produced by Python. I performed a byte-by-byte comparison of 21 exports based on my own `test.log` file, and there were no differences whatsoever. The risk in porting the formatting logic to C lay in handling edge cases: quotation marks, commas, control characters, emojis, and bytes that do not constitute valid UTF-8 (Python replaces these with  , and the C implementation does the same). For this reason, I’ve included `selftest.py`, which generates a log containing many such cases and compares the two engines across 30 different checks. I intentionally introduced four errors into the C code, and it successfully detected every one of them. In case of talking about what I didn't touch, printing lines to the screen still goes through Python (0.69 s with C, compared to 1.51 s with Python). In an actual terminal, the bottleneck will be the command-line interface itself rendering thousands of lines, so it is not worth optimizing at this stage. For now, it passes 30 checks

### 27/10/2026

- Imported `mmap`. Now, it maps the file using `mmap` on Linux and `CreateFileMapping`/`MapViewOfFile` on Windows. If that is not possible (e.g., an empty file or a pipe), it reads in blocks as before, yielding the same results.
- The code searches for the pattern within the raw bytes, jumping from one match to the next rather than scanning every line. To locate the pattern, it uses its rarest byte in conjunction with `memchr`. When the `-i` flag is used, it proceeds with the aforementioned algorithm.
- As for line counting, it processes the data in 8-byte chunks, without calling `memchr` for each individual line.
- If more than a third of the lines in a block match, the next block is processed line by line, because skipping between matches no longer offers any savings.
- New option: --no-mmap in loggrep.py (and -B in the C version) forces block-based reading.

#### Checks:

- Consistency with block-based reading: the output is identical across 6,000 comparisons using random files and options—including versions with memory sanitizers and block sizes of 1 and 64 bytes to test edge cases.
- Files larger than 4 GiB: works without overflows.
- -m with an absent pattern: responds in milliseconds.
- `selftest.py`: now performs 44 checks, including block-based reading in C and a block-boundary test that compiles a test version using my `gcc`. If I intentionally break the logic, it detects it.

-- Comments: If another program truncates the file while it is being read (“in-place” log rotation), the process may terminate. In that case, use --no-mmap. Patterns containing line breaks (\r or \n) are no longer executed in C; in 'auto' mode, they are passed to Python, and when --engine c is used, a clear error is returned. I keep using test.log, but 1 million is not enough already, to compare actual execution times, I generate a large log file using `python gen_logs.py --lines 5000000 --out big.log`. With 1 million lines, the difference is barely noticeable because it already fits into the cache.

### 03/11/2026

- Regex support in C is now implemented. Three files have been modified: log_searcher.c (version 0.5), loggrep.py, and selftest.py. My timing results using `mmap` on Windows (0.35 s vs. 0.61 s for `big.log`) confirmed that the previous step was worthwhile.
- I did not use `regex.h`—as it is not included in MinGW—nor any external library. I wrote my own engine within `log_searcher.c`: it converts the expression into an automaton and executes it using a transition table that is populated on the fly, one byte at a time. It supports literals, `.`, character classes `[...]`, `\d \w \s \D \W \S`, `\b`, `^ $ \A \Z`, groups `(…)`, `(?:…)`, and `(?P<n>…)`, the alternation operator `|`, and quantifiers `* + ? {m,n}` (including non-greedy/lazy versions). With the `-i` flag, it performs case-insensitive matching, just like Python.
- What about unsupported features? Lookarounds, backreferences like `(\w)\1`, inline flags such as `(?i)`, possessive quantifiers, and `\B` are not handled by the C engine. `loggrep.py` queries the binary beforehand; if it cannot handle a given pattern, it automatically falls back to the Python implementation—no action required on your part. If you explicitly specify `--engine c`, it will return an error explaining why.
- A change in behavior to be aware of. Previously, the Python engine performed its search across the entire line—including the trailing `\r\n`—which meant that `ERROR$` would fail when encountering files with Windows-style line endings. Now, it searches only within the actual content of the line, matching the behavior of the C engine; as a result, both engines now yield the same outcome.

#### Checks:

- Python’s regex engine: about 20,000 random expressions tested against random strings, with not a single discrepancy—including test runs with a tiny state cache (to force cache evictions) and with memory sanitizers enabled.
- Exports: the .txt, .csv, and .json files are identical between Python and C across 27 comparisons, involving a mix of profiles and regex.
- selftest.py: runs 189 checks instead of 44 like before, using 200 random expressions against the `re` module. It takes about 11 seconds here, so expect it to take a bit longer on your Windows system. I intentionally broke the engine in three different ways, and it detected the issues.

#### Speed ​​(5M lines, 393 MB, end-to-end, count mode):

- Search: -p ips ((\d{1,3}\.){3}\d{1,3}) --> Python: 36.7s | C --> 2.2s (about 16×)
- Search: -p errors (literals) -->  Python: 5.8s | C --> 0.33s

-- Comments: Regex in C reaches around 300 MB/s—well below the 3.4 GB/s achieved when searching for an uncommon literal—because it processes every line rather than jumping between matches. The next step with the most potential is to speed up the regexes by extracting a mandatory literal from each expression (for example, "Failed password"), allowing the process to jump directly to candidate lines via a "fast path." With regexes that include such literals—for instance, "Failed password|Invalid user"—performance should approach the speed of literal-based matching.

# LogGrep_Engine
## Unfinished Project
A command-line utility designed to search for patterns, regular expressions, and anomalies in massive log files (gigabytes of text), utilizing a high-speed search engine written in C, wrapped in a user-friendly Python CLI, and managed via JSON-based search profiles.

## Technical Architecture:

-- Search Engine in C (log_searcher.c): Implements efficient substring-matching algorithms (such as Boyer-Moore or finite automata) and utilizes memory-mapped file I/O (mmap) to scan millions of lines per second without exhausting RAM.

-- Python Interface and Wrapper (loggrep.py): Captures user parameters from the terminal, invokes the C binary or library, formats the results with syntax highlighting, and exports match reports.

-- Profile Management via JSON (queries.json): Enables the storage of complex filter sets, frequently used regular expressions, and categorization rules (e.g., automatically classifying critical errors as ERROR, warnings as WARN, and debug events as DEBUG).

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

-- Comments: There is 2 bottlenecks I'm trying to solve, from now on, nmap will be put on the side and for some days I'll be investigating how can I solve this and make this even faster. Maybe I will have to do a new python code just to check anyways. For now, I seem to make a solution for the first bottleneck that stresses me, but it is not solved yet.

### 26/10/2026

- made selftest.py
- tested code and solve 2 bottlenecks
- Now it is between 6-7 times faster, and the export is already nearly at the level of C alone (0.18 s). Using `--export` without `--count` also results in a speedup, though to a lesser extent, because Python still prints every line.
- A previous issue that surfaced during testing: for lines ending in \r\r\n, the behavior in Python and C did not match, because the C implementation removed only a single \r, whereas Python removes all of them. This has now been reconciled.
- If the log or export path contains non-ASCII characters (for example, `informé.csv`), the C component is bypassed for that part and Python handles it instead, because Windows loses those characters when passing them to the program. The result remains correct, though the process is slower.
- `log_searcher` includes three new options, in case you use it manually: `-o FILE`, `-F txt|csv|json`, and `-s LEVEL`.

-- Comments: The files turn out identical to those produced by Python. I performed a byte-by-byte comparison of 21 exports based on my own `test.log` file, and there were no differences whatsoever. The risk in porting the formatting logic to C lay in handling edge cases: quotation marks, commas, control characters, emojis, and bytes that do not constitute valid UTF-8 (Python replaces these with  , and the C implementation does the same). For this reason, I’ve included `selftest.py`, which generates a log containing many such cases and compares the two engines across 30 different checks. I intentionally introduced four errors into the C code, and it successfully detected every one of them. In case of talking about what I didn't touch, printing lines to the screen still goes through Python (0.69 s with C, compared to 1.51 s with Python). In an actual terminal, the bottleneck will be the command-line interface itself rendering thousands of lines, so it is not worth optimizing at this stage.

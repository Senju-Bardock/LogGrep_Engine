# LogGrep_Engine
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
- tested de code and did gcc
- integrated c in loggrep code
- some bugs have been fixed and got even way faster

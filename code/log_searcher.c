/*
 * log_searcher.c - LogGrep search engine, version 0.7
 *
 * Searches a log file for literal patterns (Boyer-Moore-Horspool, with a
 * memchr prefilter) and regular expressions (a lazily built DFA) and prints
 * each matching line to stdout.
 *
 * The file is memory-mapped (mmap on Linux/macOS, MapViewOfFile on Windows)
 * and searched in chunks of 4 MiB, small enough to stay in the CPU cache. For
 * literal patterns each pattern is looked for in the raw bytes of the chunk,
 * so lines without a match are skipped without being visited one by one;
 * regular expressions are checked line by line. If the file cannot be mapped
 * (empty, special file...) or -B is given, it is read in 1 MiB blocks and
 * checked line by line. All the ways give exactly the same results.
 *
 * Caution: if another program truncates the file while it is mapped, the
 * process may crash. Use -B to read log files that are being rotated in place.
 *
 * Usage:
 *     log_searcher [-i] [-c] [-f] [-B] [-j N] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]...
 *                  [-o OUTFILE -F txt|csv|json [-s SEVERITY]]
 *                  [-e PATTERN]... [-r REGEX]... FILE
 *     log_searcher [-i] -k -r REGEX [-r REGEX]...        (only check the regexes)
 *
 *     -e PATTERN        literal text to search for (repeatable, a line matches
 *                       if it contains ANY of the patterns). It cannot contain
 *                       a newline.
 *     -r REGEX          regular expression (repeatable); a line matches if it
 *                       contains a match of ANY -e pattern or -r expression.
 *                       Python `re` syntax, see "Regular expressions" below.
 *                       With -i the case of A-Z/a-z is ignored in -r as well.
 *     -k                only check that the -r expressions are supported: exit
 *                       code 0 if they are, 3 if not (nothing is searched)
 *     -x EXCLUDE        skip lines containing this text (repeatable)
 *     -i                ignore case for -e, -x and -r (ASCII only)
 *     -m N              stop after N matches
 *     -l LEVEL=W1,W2    define a severity level (repeatable). A matching line
 *                       gets the FIRST level, in the order given, that has any
 *                       of its words in the line as a whole word and with the
 *                       exact case (like the regex \b(?:W1|W2)\b). Words are
 *                       expected to start and end with letters, digits or '_'.
 *     -c                count only: do not print lines, just the #stats line
 *     -f                print each line as "<number, 9 wide> | [LEVEL] <text>", the format
 *                       loggrep.py shows when it does not use colours (-s gives the level
 *                       for lines that have none); with invalid UTF-8 replaced by U+FFFD
 *                       and, on Windows, CR LF line ends. Replaces the number|content format.
 *     -B                do not use memory mapping: read the file in blocks
 *     -j N              threads to search with (default: the number of cores, at
 *                       most 16; 1 = a single thread). Threads are used only when the
 *                       file is mapped, is larger than 16 MiB and -m is not given. The
 *                       output is the same whatever the number of threads.
 *     -o OUTFILE        also write every match to OUTFILE (needs -F)
 *     -F FORMAT         format of OUTFILE: txt, csv or json. The files are
 *                       byte-identical to the ones the Python exporter writes:
 *                         txt   <line>:<level or ->|<text>
 *                         csv   header line,level,text; CRLF rows
 *                         json  array of {"line", "level", "text"} objects
 *                       Text is written as UTF-8: invalid bytes are replaced
 *                       by U+FFFD, like Python's errors="replace".
 *     -s SEVERITY       level written to OUTFILE for matches without a level
 *
 * Output, one line per match:
 *     <line_number>|<line_content>              without -l
 *     <line_number>|<LEVEL>|<line_content>      with -l (LEVEL empty if no
 *                                               level matched)
 *
 * On exit a machine-readable summary is written to stderr:
 *     #stats lines=<N> bytes=<N> matches=<N>
 *     #stats lines=<N> bytes=<N> matches=<N> levels=ERROR:<N>,WARN:<N>,-:<N>
 * (the second form is used with -l; "-" counts the matches without a level).
 *
 * Exit codes (same convention as grep): 0 = matches found, 1 = no matches,
 * 2 = error, 3 = a regular expression uses unsupported syntax.
 *
 * Source layout: this file holds main(); the rest is in the lg_*.h headers next to
 * it (lg_regex.h, lg_pattern.h, lg_query.h, lg_export.h, lg_scan.h, lg_thread.h,
 * lg_platform.h). They are included here, not compiled separately, so there is a
 * single compilation unit and the compiler can inline across modules.
 *
 * Build:
 *     gcc -O2 -Wall -Wextra -o log_searcher log_searcher.c           (Windows)
 *     gcc -O2 -Wall -Wextra -pthread -o log_searcher log_searcher.c  (Linux, macOS)
 */

#include "lg_platform.h"
#include "lg_thread.h"
#include "lg_regex.h"
#include "lg_pattern.h"
#include "lg_query.h"
#include "lg_export.h"
#include "lg_scan.h"

static void usage(void) {
    fputs("Usage: log_searcher [-i] [-c] [-f] [-B] [-j N] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]... "
          "[-o OUTFILE -F txt|csv|json [-s SEVERITY]] [-e PATTERN]... [-r REGEX]... FILE\n"
          "       log_searcher [-i] -k -r REGEX [-r REGEX]...\n",
          stderr);
}

int main(int argc, char **argv) {
    Query *q = &query;
    Exporter exporter;
    memset(&exporter, 0, sizeof exporter);
    const char *include_args[MAX_PATTERNS];
    const char *exclude_args[MAX_PATTERNS];
    int check_only = 0;
    const char *level_args[MAX_LEVELS];
    int n_level_args = 0;
    const char *path = NULL;
    const char *export_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            q->ignore_case = 1;
        } else if (strcmp(argv[i], "-B") == 0) {
            q->no_mmap = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            q->count_only = 1;
        } else if (strcmp(argv[i], "-f") == 0) {
            q->console = 1;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            q->max_matches = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
            long n = strtol(argv[++i], NULL, 10);
            if (n < 0 || n > 256) {
                fputs("Error: -j expects a number of threads from 1 to 256 (0 = automatic).\n", stderr);
                return 2;
            }
            q->threads = (int)n;
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            if (q->n_include == MAX_PATTERNS) {
                fputs("Error: too many -e patterns.\n", stderr);
                return 2;
            }
            include_args[q->n_include++] = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            if (q->n_regex == MAX_PATTERNS) {
                fputs("Error: too many -r expressions.\n", stderr);
                return 2;
            }
            q->regex_args[q->n_regex++] = argv[++i];
        } else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            if (q->n_exclude == MAX_PATTERNS) {
                fputs("Error: too many -x patterns.\n", stderr);
                return 2;
            }
            exclude_args[q->n_exclude++] = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            export_path = argv[++i];
        } else if (strcmp(argv[i], "-F") == 0 && i + 1 < argc) {
            const char *fmt = argv[++i];
            exporter.fmt = strcmp(fmt, "txt") == 0   ? FMT_TXT
                           : strcmp(fmt, "csv") == 0  ? FMT_CSV
                           : strcmp(fmt, "json") == 0 ? FMT_JSON
                                                      : -1;
            if (exporter.fmt < 0) {
                fprintf(stderr, "Error: unknown export format '%s' (use txt, csv or json).\n", fmt);
                return 2;
            }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            exporter.fallback_level = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            if (n_level_args == MAX_LEVELS) {
                fputs("Error: too many -l levels.\n", stderr);
                return 2;
            }
            level_args[n_level_args++] = argv[++i];
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "Error: unknown or incomplete option '%s'.\n", argv[i]);
            usage();
            return 2;
        } else if (!path) {
            path = argv[i];
        } else {
            fputs("Error: only one FILE can be given.\n", stderr);
            usage();
            return 2;
        }
    }

    if (check_only ? q->n_regex == 0 : (!path || q->n_include + q->n_regex == 0)) {
        usage();
        return 2;
    }
    if ((export_path != NULL) != (exporter.fmt != FMT_NONE)) {
        fputs("Error: -o and -F must be used together.\n", stderr);
        return 2;
    }

    for (int i = 0; i < q->n_include; i++) { /* a match cannot span two lines */
        if (strchr(include_args[i], '\n')) {
            fputs("Error: patterns cannot contain a newline.\n", stderr);
            return 2;
        }
    }

    if (q->n_regex) {
        const char *why = NULL;
        q->dfa = dfa_build(q->regex_args, q->n_regex, q->ignore_case, &why);
        if (!q->dfa) {
            fprintf(stderr, "Error: unsupported regular expression: %s.\n", why ? why : "unknown");
            return 3;
        }
    }
    if (check_only) {
        if (q->dfa && q->dfa->has_prefilter) {
            for (int i = 0; i < q->dfa->prefilter.n; i++) {
                fputs("#prefilter ", stderr);
                for (int k = 0; k < q->dfa->prefilter.len[i]; k++) {
                    fprintf(stderr, "%02x", q->dfa->prefilter.s[i][k]);
                }
                fputc('\n', stderr);
            }
        }
        return 0;
    }

    init_tables();
    const unsigned char *fold = q->ignore_case ? fold_lower : fold_exact;
    int n_include = q->n_include, n_exclude = q->n_exclude;
    for (int i = 0; i < n_include; i++) {
        if (pattern_init(&q->include[i], include_args[i], fold) != 0) {
            fputs("Error: empty pattern or out of memory.\n", stderr);
            return 2;
        }
    }
    for (int i = 0; i < n_include; i++) {
        q->cand[q->n_cand++] = &q->include[i];
    }
    if (q->dfa && q->dfa->has_prefilter) {
        for (int i = 0; i < q->dfa->prefilter.n; i++) {
            Pattern *pf = &q->prefilter[q->n_prefilter];
            char text[LIT_LEN + 1];
            memcpy(text, q->dfa->prefilter.s[i], (size_t)q->dfa->prefilter.len[i]);
            text[q->dfa->prefilter.len[i]] = '\0';
            if (pattern_init(pf, text, fold) == 0) {
                q->cand[q->n_cand++] = pf;
                q->n_prefilter++;
            }
        }
        if (q->n_prefilter != q->dfa->prefilter.n) { /* could not set them all up: do not skip */
            q->n_cand -= q->n_prefilter;
            q->n_prefilter = 0;
        }
    }
    for (int i = 0; i < n_exclude; i++) {
        if (pattern_init(&q->exclude[i], exclude_args[i], fold) != 0) {
            fputs("Error: empty exclude pattern or out of memory.\n", stderr);
            return 2;
        }
    }
    for (int i = 0; i < n_level_args; i++) {
        if (add_level(q, level_args[i]) != 0) {
            fprintf(stderr, "Error: invalid level definition '%s' (expected NAME=WORD,WORD).\n",
                    level_args[i]);
            return 2;
        }
    }

    build_level_table(q);

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'.\n", path);
        return 2;
    }
    if (export_path) {
        exporter.fp = fopen(export_path, "wb"); /* binary: no newline translation */
        if (!exporter.fp) {
            fprintf(stderr, "Error: cannot write '%s'.\n", export_path);
            fclose(f);
            return 2;
        }
        setvbuf(exporter.fp, NULL, _IOFBF, 1u << 16);
        export_start(&exporter);
    }

#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY); /* no \n -> \r\n translation */
#endif
    setvbuf(stdout, NULL, _IOFBF, 1u << 16);

    Scanner sc;
    scanner_init(&sc, q, q->dfa, &exporter, 0, 0);
    Counters total;
    memset(&total, 0, sizeof total);
    unsigned long long line_no = 0, consumed = 0;
    int failed = 0;
    MappedFile map;
    if (!q->no_mmap && map_open(path, &map) == 0) {
        prepare_mapped(q, map.data, map.size);
        int threads = q->threads ? q->threads : lg_cpu_count();
        if (!q->threads && threads > MAX_AUTO_THREADS) {
            threads = MAX_AUTO_THREADS;
        }
        size_t chunks = chunk_count(map.size);
        /* -m makes the first matches the only ones that matter: not worth the threads */
        if (q->max_matches || map.size < PAR_MIN_BYTES || chunks < 2) {
            threads = 1;
        }
        if ((size_t)threads > chunks) {
            threads = (int)chunks;
        }
        if (threads > 1) {
            scan_mapped_parallel(q, &exporter, map.data, map.size, threads, &line_no, &total, &failed);
            consumed = map.size;
        } else {
            scan_mapped(&sc, map.data, map.size, &line_no, &consumed);
            total = sc.count;
        }
        map_close(&map);
    } else if (scan_buffered(&sc, f, &line_no, &consumed) != 0) {
        fclose(f);
        return 2;
    } else {
        total = sc.count;
    }

    int export_failed = export_finish(&exporter);
    fflush(stdout);
    fprintf(stderr, "#stats lines=%llu bytes=%llu matches=%llu", line_no, consumed, total.matches);
    if (q->n_levels) {
        fputs(" levels=", stderr);
        for (int i = 0; i < q->n_levels; i++) {
            fprintf(stderr, "%s:%llu,", q->levels[i].name, total.level[i]);
        }
        fprintf(stderr, "-:%llu", total.unclassified);
    }
    fputc('\n', stderr);

    fclose(f);
    (void)failed;
    if (export_failed) {
        fputs("Error: could not write the export file.\n", stderr);
        return 2;
    }
    return total.matches > 0 ? 0 : 1;
}

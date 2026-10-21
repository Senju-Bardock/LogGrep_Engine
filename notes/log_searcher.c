/*
 * log_searcher.c - LogGrep search engine, version 0.1
 *
 * Reads a log file in large blocks, searches every line for literal patterns
 * with the Boyer-Moore-Horspool algorithm and prints each match to stdout as:
 *
 *     <line_number>|<line_content>
 *
 * Usage:
 *     log_searcher [-i] [-m N] [-x EXCLUDE]... -e PATTERN [-e PATTERN]... FILE
 *
 *     -e PATTERN   literal text to search for (repeatable, a line matches if
 *                  it contains ANY of the patterns)
 *     -x EXCLUDE   skip lines containing this text (repeatable)
 *     -i           ignore case (ASCII only)
 *     -m N         stop after N matches
 *
 * On exit a machine-readable summary is written to stderr:
 *     #stats lines=<N> bytes=<N> matches=<N>
 *
 * Exit codes (same convention as grep): 0 = matches found, 1 = no matches,
 * 2 = error.
 *
 * Build:
 *     gcc -O2 -Wall -Wextra -o log_searcher log_searcher.c
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define BLOCK_SIZE (1u << 20) /* 1 MiB read block */
#define MAX_PATTERNS 64

/* Byte -> byte table used to compare text; lowercases when -i is active. */
static unsigned char fold[256];

typedef struct {
    unsigned char *text; /* folded pattern bytes */
    size_t len;
    size_t shift[256]; /* Horspool bad-character table */
} Pattern;

static void init_fold(int ignore_case) {
    for (int i = 0; i < 256; i++) {
        fold[i] = ignore_case ? (unsigned char)tolower(i) : (unsigned char)i;
    }
}

static int pattern_init(Pattern *p, const char *s) {
    p->len = strlen(s);
    if (p->len == 0) {
        return -1;
    }
    p->text = malloc(p->len);
    if (!p->text) {
        return -1;
    }
    for (size_t i = 0; i < p->len; i++) {
        p->text[i] = fold[(unsigned char)s[i]];
    }
    for (int c = 0; c < 256; c++) {
        p->shift[c] = p->len;
    }
    for (size_t i = 0; i + 1 < p->len; i++) {
        p->shift[p->text[i]] = p->len - 1 - i;
    }
    return 0;
}

/* Boyer-Moore-Horspool: returns 1 if the pattern occurs in hay[0..n). */
static int pattern_found(const Pattern *p, const unsigned char *hay, size_t n) {
    if (n < p->len) {
        return 0;
    }
    const size_t last = p->len - 1;
    size_t i = 0;
    while (i <= n - p->len) {
        size_t j = last;
        while (fold[hay[i + j]] == p->text[j]) {
            if (j == 0) {
                return 1;
            }
            j--;
        }
        i += p->shift[fold[hay[i + last]]];
    }
    return 0;
}

typedef struct {
    Pattern include[MAX_PATTERNS];
    int n_include;
    Pattern exclude[MAX_PATTERNS];
    int n_exclude;
    unsigned long long max_matches; /* 0 = unlimited */
} Query;

static int line_matches(const Query *q, const unsigned char *line, size_t len) {
    int hit = 0;
    for (int i = 0; i < q->n_include && !hit; i++) {
        hit = pattern_found(&q->include[i], line, len);
    }
    if (!hit) {
        return 0;
    }
    for (int i = 0; i < q->n_exclude; i++) {
        if (pattern_found(&q->exclude[i], line, len)) {
            return 0;
        }
    }
    return 1;
}

static void usage(void) {
    fputs("Usage: log_searcher [-i] [-m N] [-x EXCLUDE]... -e PATTERN [-e PATTERN]... FILE\n",
          stderr);
}

int main(int argc, char **argv) {
    Query q;
    memset(&q, 0, sizeof q);
    int ignore_case = 0;
    const char *include_args[MAX_PATTERNS];
    const char *exclude_args[MAX_PATTERNS];
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            ignore_case = 1;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            q.max_matches = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            if (q.n_include == MAX_PATTERNS) {
                fputs("Error: too many -e patterns.\n", stderr);
                return 2;
            }
            include_args[q.n_include++] = argv[++i];
        } else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            if (q.n_exclude == MAX_PATTERNS) {
                fputs("Error: too many -x patterns.\n", stderr);
                return 2;
            }
            exclude_args[q.n_exclude++] = argv[++i];
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

    if (!path || q.n_include == 0) {
        usage();
        return 2;
    }

    init_fold(ignore_case);
    for (int i = 0; i < q.n_include; i++) {
        if (pattern_init(&q.include[i], include_args[i]) != 0) {
            fputs("Error: empty pattern or out of memory.\n", stderr);
            return 2;
        }
    }
    for (int i = 0; i < q.n_exclude; i++) {
        if (pattern_init(&q.exclude[i], exclude_args[i]) != 0) {
            fputs("Error: empty exclude pattern or out of memory.\n", stderr);
            return 2;
        }
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'.\n", path);
        return 2;
    }

#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY); /* no \n -> \r\n translation */
#endif
    setvbuf(stdout, NULL, _IOFBF, 1u << 16);

    size_t cap = BLOCK_SIZE;
    size_t have = 0; /* bytes currently held in buf */
    unsigned char *buf = malloc(cap);
    if (!buf) {
        fputs("Error: out of memory.\n", stderr);
        fclose(f);
        return 2;
    }

    unsigned long long line_no = 0, matches = 0, consumed = 0;
    int stop = 0;

    while (!stop) {
        if (have == cap) { /* a single line is longer than the buffer: grow it */
            cap *= 2;
            unsigned char *bigger = realloc(buf, cap);
            if (!bigger) {
                fputs("Error: out of memory (line too long).\n", stderr);
                free(buf);
                fclose(f);
                return 2;
            }
            buf = bigger;
        }
        size_t got = fread(buf + have, 1, cap - have, f);
        if (got == 0) {
            break; /* end of file */
        }
        have += got;

        size_t start = 0;
        for (;;) {
            unsigned char *nl = memchr(buf + start, '\n', have - start);
            if (!nl) {
                break;
            }
            size_t len = (size_t)(nl - (buf + start));
            consumed += len + 1;
            if (len > 0 && buf[start + len - 1] == '\r') {
                len--;
            }
            line_no++;
            if (line_matches(&q, buf + start, len)) {
                matches++;
                printf("%llu|", line_no);
                fwrite(buf + start, 1, len, stdout);
                fputc('\n', stdout);
                if (ferror(stdout) || (q.max_matches && matches >= q.max_matches)) {
                    stop = 1;
                    break;
                }
            }
            start += (size_t)(nl - (buf + start)) + 1;
        }

        if (!stop) { /* keep the incomplete last line for the next block */
            memmove(buf, buf + start, have - start);
            have -= start;
        }
    }

    /* Last line of the file when it has no trailing newline. */
    if (!stop && have > 0) {
        size_t len = have;
        consumed += len;
        if (buf[len - 1] == '\r') {
            len--;
        }
        line_no++;
        if (line_matches(&q, buf, len)) {
            matches++;
            printf("%llu|", line_no);
            fwrite(buf, 1, len, stdout);
            fputc('\n', stdout);
        }
    }

    fflush(stdout);
    fprintf(stderr, "#stats lines=%llu bytes=%llu matches=%llu\n", line_no, consumed, matches);

    free(buf);
    fclose(f);
    return matches > 0 ? 0 : 1;
}

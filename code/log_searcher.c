/*
 * log_searcher.c - LogGrep search engine, version 0.3
 *
 * Reads a log file in large blocks, searches every line for literal patterns
 * with the Boyer-Moore-Horspool algorithm and prints each match to stdout.
 *
 * Usage:
 *     log_searcher [-i] [-c] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]...
 *                  [-o OUTFILE -F txt|csv|json [-s SEVERITY]]
 *                  -e PATTERN [-e PATTERN]... FILE
 *
 *     -e PATTERN        literal text to search for (repeatable, a line matches
 *                       if it contains ANY of the patterns)
 *     -x EXCLUDE        skip lines containing this text (repeatable)
 *     -i                ignore case for -e and -x (ASCII only)
 *     -m N              stop after N matches
 *     -l LEVEL=W1,W2    define a severity level (repeatable). A matching line
 *                       gets the FIRST level, in the order given, that has any
 *                       of its words in the line as a whole word and with the
 *                       exact case (like the regex \b(?:W1|W2)\b). Words are
 *                       expected to start and end with letters, digits or '_'.
 *     -c                count only: do not print lines, just the #stats line
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
#define MAX_LEVELS 16
#define MAX_LEVEL_WORDS 16
#define MAX_LEVEL_NAME 32
#define MAX_WORD_LEN 256
#define NOT_FOUND ((size_t)-1)

/* Byte -> byte tables used to compare text. */
static unsigned char fold_exact[256];
static unsigned char fold_lower[256];

typedef struct {
    unsigned char *text; /* pattern bytes, already folded */
    size_t len;
    const unsigned char *fold; /* which table this pattern is compared with */
    size_t shift[256];         /* Horspool bad-character table */
} Pattern;

typedef struct {
    char name[MAX_LEVEL_NAME];
    Pattern words[MAX_LEVEL_WORDS];
    int n_words;
    unsigned long long count;
} Level;

enum { FMT_NONE = 0, FMT_TXT, FMT_CSV, FMT_JSON };

typedef struct {
    Pattern include[MAX_PATTERNS];
    int n_include;
    Pattern exclude[MAX_PATTERNS];
    int n_exclude;
    Level levels[MAX_LEVELS];
    int n_levels;
    unsigned long long unclassified; /* matches with no level */
    unsigned long long max_matches;  /* 0 = unlimited */
    int count_only;
    FILE *export_fp;                 /* NULL when -o is not used */
    int export_fmt;
    unsigned long long exported;     /* records written to the export file */
    const char *fallback_level;      /* level exported when none matched (-s) */
} Query;

static Query query; /* static: it is too big for the stack */

static void init_tables(void) {
    for (int i = 0; i < 256; i++) {
        fold_exact[i] = (unsigned char)i;
        fold_lower[i] = (unsigned char)tolower(i);
    }
}

static int pattern_init(Pattern *p, const char *s, const unsigned char *fold) {
    p->len = strlen(s);
    if (p->len == 0) {
        return -1;
    }
    p->text = malloc(p->len);
    if (!p->text) {
        return -1;
    }
    p->fold = fold;
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

/* Boyer-Moore-Horspool: first occurrence at or after 'from', or NOT_FOUND. */
static size_t pattern_find(const Pattern *p, const unsigned char *hay, size_t n, size_t from) {
    if (from > n || n - from < p->len) {
        return NOT_FOUND;
    }
    const unsigned char *fold = p->fold;
    const size_t last = p->len - 1;
    size_t i = from;
    while (i <= n - p->len) {
        size_t j = last;
        while (fold[hay[i + j]] == p->text[j]) {
            if (j == 0) {
                return i;
            }
            j--;
        }
        i += p->shift[fold[hay[i + last]]];
    }
    return NOT_FOUND;
}

static int is_word_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

/* The pattern occurs as a whole word (letters, digits and '_' around it). */
static int word_found(const Pattern *p, const unsigned char *hay, size_t n) {
    size_t from = 0;
    for (;;) {
        size_t pos = pattern_find(p, hay, n, from);
        if (pos == NOT_FOUND) {
            return 0;
        }
        size_t end = pos + p->len;
        if ((pos == 0 || !is_word_char(hay[pos - 1])) && (end == n || !is_word_char(hay[end]))) {
            return 1;
        }
        from = pos + 1;
    }
}

static int line_matches(const Query *q, const unsigned char *line, size_t len) {
    int hit = 0;
    for (int i = 0; i < q->n_include && !hit; i++) {
        hit = pattern_find(&q->include[i], line, len, 0) != NOT_FOUND;
    }
    if (!hit) {
        return 0;
    }
    for (int i = 0; i < q->n_exclude; i++) {
        if (pattern_find(&q->exclude[i], line, len, 0) != NOT_FOUND) {
            return 0;
        }
    }
    return 1;
}

/* Index of the first level that matches the line, or -1. */
static int classify(const Query *q, const unsigned char *line, size_t len) {
    for (int i = 0; i < q->n_levels; i++) {
        const Level *lv = &q->levels[i];
        for (int w = 0; w < lv->n_words; w++) {
            if (word_found(&lv->words[w], line, len)) {
                return i;
            }
        }
    }
    return -1;
}

/* Parses "NAME=WORD1,WORD2" and adds it to the query. Returns 0 on success. */
static int add_level(Query *q, const char *spec) {
    if (q->n_levels == MAX_LEVELS) {
        return -1;
    }
    const char *eq = strchr(spec, '=');
    if (!eq || eq == spec) {
        return -1;
    }
    size_t name_len = (size_t)(eq - spec);
    if (name_len >= MAX_LEVEL_NAME || memchr(spec, '|', name_len) || memchr(spec, ',', name_len) ||
        memchr(spec, ':', name_len)) {
        return -1;
    }
    Level *lv = &q->levels[q->n_levels];
    memcpy(lv->name, spec, name_len);
    lv->name[name_len] = '\0';
    if (strcmp(lv->name, "-") == 0) { /* reserved for "no level" in #stats */
        return -1;
    }

    const char *p = eq + 1;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t wlen = comma ? (size_t)(comma - p) : strlen(p);
        if (wlen == 0 || wlen >= MAX_WORD_LEN || lv->n_words == MAX_LEVEL_WORDS) {
            return -1;
        }
        char word[MAX_WORD_LEN];
        memcpy(word, p, wlen);
        word[wlen] = '\0';
        if (pattern_init(&lv->words[lv->n_words], word, fold_exact) != 0) {
            return -1;
        }
        lv->n_words++;
        p = comma ? comma + 1 : p + wlen;
    }
    if (lv->n_words == 0) {
        return -1;
    }
    q->n_levels++;
    return 0;
}

/* ---- Export (-o) -------------------------------------------------------- */

/* Length of the UTF-8 sequence starting at s[0]. If it is ill-formed, *valid
 * is set to 0 and the result is the length of its maximal invalid subpart,
 * which is what Python replaces with a single U+FFFD. */
static size_t utf8_seq(const unsigned char *s, size_t n, int *valid) {
    unsigned char c = s[0];
    size_t need;
    unsigned char lo = 0x80, hi = 0xBF;
    *valid = 1;
    if (c < 0x80) {
        return 1;
    } else if (c >= 0xC2 && c <= 0xDF) {
        need = 1;
    } else if (c >= 0xE0 && c <= 0xEF) {
        need = 2;
        if (c == 0xE0) {
            lo = 0xA0;
        } else if (c == 0xED) {
            hi = 0x9F;
        }
    } else if (c >= 0xF0 && c <= 0xF4) {
        need = 3;
        if (c == 0xF0) {
            lo = 0x90;
        } else if (c == 0xF4) {
            hi = 0x8F;
        }
    } else {
        *valid = 0;
        return 1;
    }
    if (n < 2 || s[1] < lo || s[1] > hi) {
        *valid = 0;
        return 1;
    }
    for (size_t i = 2; i <= need; i++) {
        if (i >= n || s[i] < 0x80 || s[i] > 0xBF) {
            *valid = 0;
            return i;
        }
    }
    return need + 1;
}

static unsigned char *clean_buf;
static size_t clean_cap;

/* Returns the text as valid UTF-8: the same pointer when it already is,
 * otherwise a copy where every invalid subpart became U+FFFD. */
static const unsigned char *utf8_clean(const unsigned char *s, size_t n, size_t *out_len) {
    size_t i = 0;
    while (i < n) {
        if (s[i] < 0x80) {
            i++;
            continue;
        }
        int valid;
        size_t k = utf8_seq(s + i, n - i, &valid);
        if (!valid) {
            break;
        }
        i += k;
    }
    if (i == n) {
        *out_len = n;
        return s;
    }

    if (clean_cap < n * 3) {
        unsigned char *bigger = realloc(clean_buf, n * 3);
        if (!bigger) {
            fputs("Error: out of memory.\n", stderr);
            exit(2);
        }
        clean_buf = bigger;
        clean_cap = n * 3;
    }
    memcpy(clean_buf, s, i);
    size_t o = i;
    while (i < n) {
        int valid;
        size_t k = utf8_seq(s + i, n - i, &valid);
        if (valid) {
            memcpy(clean_buf + o, s + i, k);
            o += k;
        } else {
            clean_buf[o++] = 0xEF;
            clean_buf[o++] = 0xBF;
            clean_buf[o++] = 0xBD;
        }
        i += k;
    }
    *out_len = o;
    return clean_buf;
}

/* CSV field with the same quoting rules as Python's csv module (excel dialect). */
static void write_csv_field(FILE *fp, const unsigned char *s, size_t n) {
    int quote = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == ',' || s[i] == '"' || s[i] == '\r' || s[i] == '\n') {
            quote = 1;
            break;
        }
    }
    if (!quote) {
        fwrite(s, 1, n, fp);
        return;
    }
    fputc('"', fp);
    size_t start = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '"') {
            fwrite(s + start, 1, i - start + 1, fp); /* up to and including the quote */
            fputc('"', fp);                          /* ...and double it */
            start = i + 1;
        }
    }
    fwrite(s + start, 1, n - start, fp);
    fputc('"', fp);
}

/* JSON string with the same escaping as Python's json.dumps(ensure_ascii=False). */
static void write_json_string(FILE *fp, const unsigned char *s, size_t n) {
    fputc('"', fp);
    size_t start = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = s[i];
        if (c >= 0x20 && c != '"' && c != '\\') {
            continue;
        }
        fwrite(s + start, 1, i - start, fp);
        switch (c) {
        case '"': fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n", fp); break;
        case '\r': fputs("\\r", fp); break;
        case '\t': fputs("\\t", fp); break;
        case '\b': fputs("\\b", fp); break;
        case '\f': fputs("\\f", fp); break;
        default: fprintf(fp, "\\u%04x", c);
        }
        start = i + 1;
    }
    fwrite(s + start, 1, n - start, fp);
    fputc('"', fp);
}

static void export_start(Query *q) {
    if (q->export_fmt == FMT_CSV) {
        fputs("line,level,text\r\n", q->export_fp);
    } else if (q->export_fmt == FMT_JSON) {
        fputs("[\n", q->export_fp);
    }
}

static void export_match(Query *q, unsigned long long line_no, const char *level,
                         const unsigned char *line, size_t len) {
    FILE *fp = q->export_fp;
    size_t n;
    const unsigned char *text = utf8_clean(line, len, &n);
    size_t level_len = level ? strlen(level) : 0;

    if (q->export_fmt == FMT_TXT) {
        fprintf(fp, "%llu:%s|", line_no, level ? level : "-");
        fwrite(text, 1, n, fp);
        fputc('\n', fp);
    } else if (q->export_fmt == FMT_CSV) {
        fprintf(fp, "%llu,", line_no);
        write_csv_field(fp, (const unsigned char *)(level ? level : ""), level_len);
        fputc(',', fp);
        write_csv_field(fp, text, n);
        fputs("\r\n", fp);
    } else {
        fputs(q->exported ? ",\n  {\"line\": " : "  {\"line\": ", fp);
        fprintf(fp, "%llu, \"level\": ", line_no);
        if (level) {
            write_json_string(fp, (const unsigned char *)level, level_len);
        } else {
            fputs("null", fp);
        }
        fputs(", \"text\": ", fp);
        write_json_string(fp, text, n);
        fputc('}', fp);
    }
    q->exported++;
}

/* Handles one line. Returns 1 when the search must stop. */
static int handle_line(Query *q, unsigned long long line_no, const unsigned char *line, size_t len,
                       unsigned long long *matches) {
    if (!line_matches(q, line, len)) {
        return 0;
    }
    (*matches)++;

    int level = q->n_levels ? classify(q, line, len) : -1;
    if (level >= 0) {
        q->levels[level].count++;
    } else {
        q->unclassified++;
    }

    if (q->export_fp) {
        export_match(q, line_no, level >= 0 ? q->levels[level].name : q->fallback_level, line, len);
    }

    if (!q->count_only) {
        if (q->n_levels) {
            printf("%llu|%s|", line_no, level >= 0 ? q->levels[level].name : "");
        } else {
            printf("%llu|", line_no);
        }
        fwrite(line, 1, len, stdout);
        fputc('\n', stdout);
        if (ferror(stdout)) {
            return 1;
        }
    }
    return q->max_matches && *matches >= q->max_matches;
}

static void usage(void) {
    fputs("Usage: log_searcher [-i] [-c] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]... "
          "[-o OUTFILE -F txt|csv|json [-s SEVERITY]] -e PATTERN [-e PATTERN]... FILE\n",
          stderr);
}

int main(int argc, char **argv) {
    Query *q = &query;
    int ignore_case = 0;
    const char *include_args[MAX_PATTERNS];
    const char *exclude_args[MAX_PATTERNS];
    const char *level_args[MAX_LEVELS];
    int n_level_args = 0;
    const char *path = NULL;
    const char *export_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            ignore_case = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            q->count_only = 1;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            q->max_matches = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            if (q->n_include == MAX_PATTERNS) {
                fputs("Error: too many -e patterns.\n", stderr);
                return 2;
            }
            include_args[q->n_include++] = argv[++i];
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
            q->export_fmt = strcmp(fmt, "txt") == 0   ? FMT_TXT
                            : strcmp(fmt, "csv") == 0  ? FMT_CSV
                            : strcmp(fmt, "json") == 0 ? FMT_JSON
                                                       : -1;
            if (q->export_fmt < 0) {
                fprintf(stderr, "Error: unknown export format '%s' (use txt, csv or json).\n", fmt);
                return 2;
            }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            q->fallback_level = argv[++i];
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

    if (!path || q->n_include == 0) {
        usage();
        return 2;
    }
    if ((export_path != NULL) != (q->export_fmt != FMT_NONE)) {
        fputs("Error: -o and -F must be used together.\n", stderr);
        return 2;
    }

    init_tables();
    const unsigned char *fold = ignore_case ? fold_lower : fold_exact;
    int n_include = q->n_include, n_exclude = q->n_exclude;
    for (int i = 0; i < n_include; i++) {
        if (pattern_init(&q->include[i], include_args[i], fold) != 0) {
            fputs("Error: empty pattern or out of memory.\n", stderr);
            return 2;
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

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'.\n", path);
        return 2;
    }
    if (export_path) {
        q->export_fp = fopen(export_path, "wb"); /* binary: no newline translation */
        if (!q->export_fp) {
            fprintf(stderr, "Error: cannot write '%s'.\n", export_path);
            fclose(f);
            return 2;
        }
        setvbuf(q->export_fp, NULL, _IOFBF, 1u << 16);
        export_start(q);
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
            while (len > 0 && buf[start + len - 1] == '\r') { /* CRLF, like Python's rstrip */
                len--;
            }
            line_no++;
            if (handle_line(q, line_no, buf + start, len, &matches)) {
                stop = 1;
                break;
            }
            start = (size_t)(nl - buf) + 1;
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
        while (len > 0 && buf[len - 1] == '\r') {
            len--;
        }
        line_no++;
        handle_line(q, line_no, buf, len, &matches);
    }

    int export_failed = 0;
    if (q->export_fp) {
        if (q->export_fmt == FMT_JSON) {
            fputs("\n]\n", q->export_fp);
        }
        export_failed = ferror(q->export_fp) != 0;
        if (fclose(q->export_fp) != 0) {
            export_failed = 1;
        }
    }
    fflush(stdout);
    fprintf(stderr, "#stats lines=%llu bytes=%llu matches=%llu", line_no, consumed, matches);
    if (q->n_levels) {
        fputs(" levels=", stderr);
        for (int i = 0; i < q->n_levels; i++) {
            fprintf(stderr, "%s:%llu,", q->levels[i].name, q->levels[i].count);
        }
        fprintf(stderr, "-:%llu", q->unclassified);
    }
    fputc('\n', stderr);

    free(buf);
    fclose(f);
    if (export_failed) {
        fputs("Error: could not write the export file.\n", stderr);
        return 2;
    }
    return matches > 0 ? 0 : 1;
}

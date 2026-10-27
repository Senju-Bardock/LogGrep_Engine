/*
 * log_searcher.c - LogGrep search engine, version 0.4
 *
 * Searches a log file for literal patterns with the Boyer-Moore-Horspool
 * algorithm and prints each matching line to stdout.
 *
 * The file is memory-mapped (mmap on Linux/macOS, MapViewOfFile on Windows)
 * and searched in chunks of 4 MiB (small enough to stay in the CPU cache):
 * each pattern is looked for in the raw bytes of the chunk, so lines without
 * a match are skipped without being visited one by one. If the file cannot be mapped (empty, special file...)
 * or -B is given, it is read in 1 MiB blocks and checked line by line; both
 * ways give exactly the same results.
 *
 * Caution: if another program truncates the file while it is mapped, the
 * process may crash. Use -B to read log files that are being rotated in place.
 *
 * Usage:
 *     log_searcher [-i] [-c] [-B] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]...
 *                  [-o OUTFILE -F txt|csv|json [-s SEVERITY]]
 *                  -e PATTERN [-e PATTERN]... FILE
 *
 *     -e PATTERN        literal text to search for (repeatable, a line matches
 *                       if it contains ANY of the patterns). It cannot contain
 *                       a newline.
 *     -x EXCLUDE        skip lines containing this text (repeatable)
 *     -i                ignore case for -e and -x (ASCII only)
 *     -m N              stop after N matches
 *     -l LEVEL=W1,W2    define a severity level (repeatable). A matching line
 *                       gets the FIRST level, in the order given, that has any
 *                       of its words in the line as a whole word and with the
 *                       exact case (like the regex \b(?:W1|W2)\b). Words are
 *                       expected to start and end with letters, digits or '_'.
 *     -c                count only: do not print lines, just the #stats line
 *     -B                do not use memory mapping: read the file in blocks
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

#ifndef _WIN32
#define _POSIX_C_SOURCE 200112L /* mmap, fstat, posix_madvise */
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define BLOCK_SIZE (1u << 20) /* 1 MiB read block */
#define MAX_PATTERNS 64
#define MAX_LEVELS 16
#define MAX_LEVEL_WORDS 16
#define MAX_LEVEL_NAME 32
#define MAX_WORD_LEN 256
#define NOT_FOUND ((size_t)-1)
#define UNKNOWN ((size_t)-2)
#ifndef MAP_CHUNK
#define MAP_CHUNK ((size_t)4 << 20) /* 4 MiB searched at a time when mapped */
#endif

/* Byte -> byte tables used to compare text. */
static unsigned char fold_exact[256];
static unsigned char fold_lower[256];

typedef struct {
    unsigned char *text; /* pattern bytes, already folded */
    size_t len;
    const unsigned char *fold; /* which table this pattern is compared with */
    size_t shift[256];         /* Horspool bad-character table */
    size_t rare;               /* index of the least frequent byte (see pattern_pick_rare) */
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
    int no_mmap;                     /* -B: always read in blocks */
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

/* Picks the byte of the pattern that is rarest in the text, judging by the
 * byte frequencies of a sample of the file. */
static void pattern_pick_rare(Pattern *p, const unsigned long long freq[256]) {
    p->rare = 0;
    for (size_t i = 1; i < p->len; i++) {
        if (freq[p->text[i]] < freq[p->text[p->rare]]) {
            p->rare = i;
        }
    }
}

/* Same result as pattern_find, but for case-sensitive patterns it looks for the
 * rarest byte of the pattern with memchr (which is vectorised in the C library)
 * and only compares the whole pattern around those candidates. This reads the
 * text at memory speed instead of stepping through it with Horspool shifts. */
static size_t pattern_find_fast(const Pattern *p, const unsigned char *hay, size_t n, size_t from) {
    if (p->fold != fold_exact) { /* -i: compare through the folding table */
        return pattern_find(p, hay, n, from);
    }
    if (from > n || n - from < p->len) {
        return NOT_FOUND;
    }
    const unsigned char rare_byte = p->text[p->rare];
    size_t pos = from + p->rare;                 /* first position where the rare byte may be */
    const size_t last = n - p->len + p->rare;    /* last position where it may be */
    while (pos <= last) {
        const unsigned char *hit = memchr(hay + pos, rare_byte, last - pos + 1);
        if (!hit) {
            return NOT_FOUND;
        }
        size_t at = (size_t)(hit - hay);
        if (memcmp(hay + at - p->rare, p->text, p->len) == 0) {
            return at - p->rare;
        }
        pos = at + 1;
    }
    return NOT_FOUND;
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

/* ---- Scanning ----------------------------------------------------------- */

/* Reads the file in blocks and checks it line by line. Returns -1 on error. */
static int scan_buffered(Query *q, FILE *f, unsigned long long *lines_out,
                         unsigned long long *consumed_out, unsigned long long *matches_out) {
    size_t cap = BLOCK_SIZE;
    size_t have = 0; /* bytes currently held in buf */
    unsigned char *buf = malloc(cap);
    if (!buf) {
        fputs("Error: out of memory.\n", stderr);
        return -1;
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
                return -1;
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

    free(buf);
    *lines_out = line_no;
    *consumed_out = consumed;
    *matches_out = matches;
    return 0;
}

typedef struct {
    const unsigned char *data;
    size_t size;
#ifdef _WIN32
    HANDLE file;
    HANDLE mapping;
#endif
} MappedFile;

/* Maps the whole file read-only. Returns 0 on success, -1 if it cannot be
 * mapped (empty file, special file, larger than the address space...): the
 * caller then falls back to buffered reads. */
static int map_open(const char *path, MappedFile *m) {
    memset(m, 0, sizeof *m);
#ifdef _WIN32
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        (unsigned long long)size.QuadPart > (unsigned long long)SIZE_MAX) {
        CloseHandle(file);
        return -1;
    }
    HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) {
        CloseHandle(file);
        return -1;
    }
    void *view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(mapping);
        CloseHandle(file);
        return -1;
    }
    m->data = view;
    m->size = (size_t)size.QuadPart;
    m->file = file;
    m->mapping = mapping;
    return 0;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (unsigned long long)st.st_size > (unsigned long long)SIZE_MAX) {
        close(fd);
        return -1;
    }
    void *view = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd); /* the mapping stays valid */
    if (view == MAP_FAILED) {
        return -1;
    }
#ifdef POSIX_MADV_SEQUENTIAL
    posix_madvise(view, (size_t)st.st_size, POSIX_MADV_SEQUENTIAL);
#endif
    m->data = view;
    m->size = (size_t)st.st_size;
    return 0;
#endif
}

static void map_close(MappedFile *m) {
#ifdef _WIN32
    UnmapViewOfFile(m->data);
    CloseHandle(m->mapping);
    CloseHandle(m->file);
#else
    munmap((void *)m->data, m->size);
#endif
}

/* Number of '\n' bytes in p[0..n). Works on 8 bytes at a time with plain integer
 * arithmetic (no memchr call per line, no special instructions needed). */
static unsigned long long count_newlines(const unsigned char *p, size_t n) {
    const uint64_t newline = 0x0A0A0A0A0A0A0A0AULL;
    const uint64_t low7 = 0x7F7F7F7F7F7F7F7FULL;
    const uint64_t pairs = 0x00FF00FF00FF00FFULL;
    unsigned long long count = 0;
    size_t i = 0;

    while (n - i >= 8) {
        size_t words = (n - i) / 8;
        if (words > 255) {
            words = 255; /* a byte lane of 'acc' holds at most 255 */
        }
        uint64_t acc = 0;
        for (size_t w = 0; w < words; w++, i += 8) {
            uint64_t x;
            memcpy(&x, p + i, 8);
            x ^= newline; /* bytes that were '\n' are now 0 */
            uint64_t zero = ~(((x & low7) + low7) | x | low7); /* 0x80 in each zero byte */
            acc += zero >> 7;
        }
        acc = (acc & pairs) + ((acc >> 8) & pairs);
        count += (acc * 0x0001000100010001ULL) >> 48;
    }
    for (; i < n; i++) {
        count += p[i] == '\n';
    }
    return count;
}

typedef struct {
    unsigned long long lines; /* lines covered (up to the last one handled when stopped) */
    size_t consumed;          /* bytes covered */
    int stop;                 /* the search must end */
} RegionResult;

/* Searches a region that starts at the beginning of a line and ends at the end
 * of a line (or of the file). Instead of visiting every line, it looks for the
 * patterns in the raw bytes, jumps to the line that contains the first
 * occurrence, checks it and continues after it. Patterns contain no newline,
 * so no match can span two lines. */
static RegionResult scan_region(Query *q, const unsigned char *data, size_t size,
                                unsigned long long first_line_no, unsigned long long *matches) {
    RegionResult r = {0, 0, 0};
    size_t next[MAX_PATTERNS]; /* next occurrence of each pattern at or after 'cursor' */
    for (int i = 0; i < q->n_include; i++) {
        next[i] = UNKNOWN;
    }
    size_t cursor = 0;                   /* start of the first line not handled yet */
    unsigned long long lines_before = 0; /* lines before 'cursor' */

    while (cursor < size) {
        size_t best = NOT_FOUND;
        for (int i = 0; i < q->n_include; i++) {
            if (next[i] == NOT_FOUND) {
                continue; /* this pattern does not occur any more */
            }
            if (next[i] == UNKNOWN || next[i] < cursor) {
                next[i] = pattern_find_fast(&q->include[i], data, size, cursor);
            }
            if (next[i] < best) {
                best = next[i];
            }
        }
        if (best == NOT_FOUND) {
            break;
        }

        size_t ls = best; /* start of the line that holds the occurrence */
        while (ls > cursor && data[ls - 1] != '\n') {
            ls--;
        }
        lines_before += count_newlines(data + cursor, ls - cursor);
        const unsigned char *nl = memchr(data + best, '\n', size - best);
        size_t le = nl ? (size_t)(nl - data) : size;
        size_t len = le - ls;
        while (len > 0 && data[ls + len - 1] == '\r') { /* CRLF, like Python's rstrip */
            len--;
        }

        int stop = handle_line(q, first_line_no + lines_before, data + ls, len, matches);
        lines_before++;
        cursor = nl ? le + 1 : size;
        if (stop) {
            r.lines = lines_before;
            r.consumed = cursor;
            r.stop = 1;
            return r;
        }
    }

    if (cursor < size) { /* the rest has no more matches: just count its lines */
        lines_before += count_newlines(data + cursor, size - cursor);
        if (data[size - 1] != '\n') {
            lines_before++;
        }
    }
    r.lines = lines_before;
    r.consumed = size;
    return r;
}

/* Same as scan_region but visits every line. It is faster when a large share of
 * the lines match, because then jumping from match to match saves nothing. */
static RegionResult scan_region_lines(Query *q, const unsigned char *data, size_t size,
                                      unsigned long long first_line_no, unsigned long long *matches) {
    RegionResult r = {0, 0, 0};
    size_t start = 0;
    unsigned long long lines_before = 0;

    while (start < size) {
        const unsigned char *nl = memchr(data + start, '\n', size - start);
        size_t end = nl ? (size_t)(nl - data) : size;
        size_t len = end - start;
        while (len > 0 && data[start + len - 1] == '\r') { /* CRLF, like Python's rstrip */
            len--;
        }
        int stop = handle_line(q, first_line_no + lines_before, data + start, len, matches);
        lines_before++;
        start = nl ? end + 1 : size;
        if (stop) {
            r.lines = lines_before;
            r.consumed = start;
            r.stop = 1;
            return r;
        }
    }
    r.lines = lines_before;
    r.consumed = size;
    return r;
}

/* Searches a whole mapped file, one chunk (ending at a line end) at a time, so
 * that the first results appear quickly even in huge files. Each chunk is
 * searched in the way that suits the density of matches seen in the previous
 * one: jumping between matches when they are sparse, line by line when more
 * than a third of the lines match. */
static void scan_mapped(Query *q, const unsigned char *data, size_t size,
                        unsigned long long *lines_out, unsigned long long *consumed_out,
                        unsigned long long *matches_out) {
    unsigned long long lines = 0, matches = 0;
    size_t pos = 0, consumed = 0;
    int stop = 0;
    int dense = 0; /* the previous chunk had many matches */

    unsigned long long freq[256] = {0}; /* byte frequencies in the first 1 MiB */
    size_t sample = size < ((size_t)1 << 20) ? size : ((size_t)1 << 20);
    for (size_t i = 0; i < sample; i++) {
        freq[data[i]]++;
    }
    for (int i = 0; i < q->n_include; i++) {
        pattern_pick_rare(&q->include[i], freq);
    }

    while (!stop && pos < size) {
        size_t end = size - pos > MAP_CHUNK ? pos + MAP_CHUNK : size;
        if (end < size) { /* move the end to the end of its line */
            const unsigned char *nl = memchr(data + end - 1, '\n', size - (end - 1));
            end = nl ? (size_t)(nl - data) + 1 : size;
        }
        unsigned long long matches_before = matches;
        RegionResult r = dense ? scan_region_lines(q, data + pos, end - pos, lines + 1, &matches)
                               : scan_region(q, data + pos, end - pos, lines + 1, &matches);
        dense = r.lines > 0 && (matches - matches_before) * 3 > r.lines;
        lines += r.lines;
        consumed = pos + r.consumed;
        stop = r.stop;
        pos = end;
    }
    if (!stop) {
        consumed = size;
    }
    *lines_out = lines;
    *consumed_out = consumed;
    *matches_out = matches;
}

static void usage(void) {
    fputs("Usage: log_searcher [-i] [-c] [-B] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]... "
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
        } else if (strcmp(argv[i], "-B") == 0) {
            q->no_mmap = 1;
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

    for (int i = 0; i < q->n_include; i++) { /* a match cannot span two lines */
        if (strchr(include_args[i], '\n')) {
            fputs("Error: patterns cannot contain a newline.\n", stderr);
            return 2;
        }
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

    unsigned long long line_no = 0, matches = 0, consumed = 0;
    MappedFile map;
    if (!q->no_mmap && map_open(path, &map) == 0) {
        scan_mapped(q, map.data, map.size, &line_no, &consumed, &matches);
        map_close(&map);
    } else if (scan_buffered(q, f, &line_no, &consumed, &matches) != 0) {
        fclose(f);
        return 2;
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

    fclose(f);
    if (export_failed) {
        fputs("Error: could not write the export file.\n", stderr);
        return 2;
    }
    return matches > 0 ? 0 : 1;
}

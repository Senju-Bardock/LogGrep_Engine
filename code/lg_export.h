/* lg_export.h - export file writers (txt, csv, json) and UTF-8 cleaning. */
#ifndef LG_EXPORT_H
#define LG_EXPORT_H

#include "lg_platform.h"

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

enum { FMT_NONE = 0, FMT_TXT, FMT_CSV, FMT_JSON };

/* The export file (-o). Only one thread writes to it. */
typedef struct {
    FILE *fp;                    /* NULL when -o is not used */
    int fmt;
    unsigned long long exported; /* records written so far */
    const char *fallback_level;  /* level written when a match has none (-s) */
} Exporter;

static void export_start(Exporter *ex) {
    if (ex->fmt == FMT_CSV) {
        fputs("line,level,text\r\n", ex->fp);
    } else if (ex->fmt == FMT_JSON) {
        fputs("[\n", ex->fp);
    }
}

static void export_match(Exporter *ex, unsigned long long line_no, const char *level,
                         const unsigned char *line, size_t len) {
    FILE *fp = ex->fp;
    size_t n;
    const unsigned char *text = utf8_clean(line, len, &n);
    size_t level_len = level ? strlen(level) : 0;

    if (ex->fmt == FMT_TXT) {
        fprintf(fp, "%llu:%s|", line_no, level ? level : "-");
        fwrite(text, 1, n, fp);
        fputc('\n', fp);
    } else if (ex->fmt == FMT_CSV) {
        fprintf(fp, "%llu,", line_no);
        write_csv_field(fp, (const unsigned char *)(level ? level : ""), level_len);
        fputc(',', fp);
        write_csv_field(fp, text, n);
        fputs("\r\n", fp);
    } else {
        fputs(ex->exported ? ",\n  {\"line\": " : "  {\"line\": ", fp);
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
    ex->exported++;
}

/* Closes the export file. Returns 1 if anything could not be written. */
static int export_finish(Exporter *ex) {
    if (!ex->fp) {
        return 0;
    }
    if (ex->fmt == FMT_JSON) {
        fputs("\n]\n", ex->fp);
    }
    int failed = ferror(ex->fp) != 0;
    if (fclose(ex->fp) != 0) {
        failed = 1;
    }
    ex->fp = NULL;
    return failed;
}


#endif

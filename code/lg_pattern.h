/* lg_pattern.h - literal search (Boyer-Moore-Horspool and a memchr prefilter) and line counting. */
#ifndef LG_PATTERN_H
#define LG_PATTERN_H

#include "lg_platform.h"

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


#endif

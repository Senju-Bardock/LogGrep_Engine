/* lg_query.h - what to search for: the Query, the level classifier and the line test. */
#ifndef LG_QUERY_H
#define LG_QUERY_H

#include "lg_regex.h"
#include "lg_pattern.h"

typedef struct {
    char name[MAX_LEVEL_NAME];
    Pattern words[MAX_LEVEL_WORDS];
    int n_words;
} Level;

typedef struct {
    const unsigned char *text;
    size_t len;
    int level;
} LevelWord;

/* What to search for and how. It is filled in by main() and never changes
 * afterwards, so any number of threads can read it at the same time. */
typedef struct {
    Pattern include[MAX_PATTERNS]; /* -e */
    int n_include;
    Pattern exclude[MAX_PATTERNS]; /* -x */
    int n_exclude;
    const char *regex_args[MAX_PATTERNS]; /* -r (text, to build one automaton per thread) */
    int n_regex;
    int ignore_case;
    Dfa *dfa;                   /* the main thread's automaton, NULL if there is no -r */
    Pattern prefilter[LIT_MAX]; /* strings found by lit_pick_prefilter() */
    int n_prefilter;
    Pattern *cand[MAX_PATTERNS + LIT_MAX]; /* what the chunk scan looks for: -e + prefilter */
    int n_cand;
    Level levels[MAX_LEVELS]; /* -l */
    int n_levels;
    /* All the level words sorted by first byte, for classify(). */
    LevelWord level_words[MAX_LEVELS * MAX_LEVEL_WORDS];
    int level_start[257]; /* words starting with byte b: level_words[level_start[b] .. level_start[b+1]) */
    unsigned long long max_matches; /* -m, 0 = unlimited */
    int count_only;                 /* -c */
    int no_mmap;                    /* -B: always read in blocks */
    int threads;                    /* -j, 0 = automatic */
} Query;

static Query query; /* static: it is too big for the stack */

/* The totals of one scan (or of a part of it). */
typedef struct {
    unsigned long long matches;
    unsigned long long unclassified; /* matches with no level */
    unsigned long long level[MAX_LEVELS];
} Counters;

static void counters_add(Counters *total, const Counters *part) {
    total->matches += part->matches;
    total->unclassified += part->unclassified;
    for (int i = 0; i < MAX_LEVELS; i++) {
        total->level[i] += part->level[i];
    }
}

/* Does the line match? 'dfa' is the caller's own automaton (it changes as it
 * learns, so threads cannot share one). */
static int line_matches(const Query *q, Dfa *dfa, const unsigned char *line, size_t len) {
    int hit = 0;
    for (int i = 0; i < q->n_include && !hit; i++) {
        hit = pattern_find(&q->include[i], line, len, 0) != NOT_FOUND;
    }
    if (!hit && dfa) {
        hit = dfa_search(dfa, line, len);
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

static int is_word_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

/* Index of the first level that has a word in the line, or -1. A word counts when
 * it stands on its own, i.e. it matches \bword\b (what the Python engine uses).
 * Instead of searching each word through the whole line, one pass looks at the
 * bytes that can start a word and only compares there. */
static int classify(const Query *q, const unsigned char *line, size_t len) {
    int best = q->n_levels;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = line[i];
        int from = q->level_start[c], to = q->level_start[c + 1];
        for (int k = from; k < to; k++) {
            const LevelWord *w = &q->level_words[k];
            if (w->level >= best || len - i < w->len || memcmp(line + i, w->text, w->len) != 0) {
                continue;
            }
            size_t end = i + w->len;
            int before = i > 0 && is_word_char(line[i - 1]);
            int after = end < len && is_word_char(line[end]);
            if (before != is_word_char(w->text[0]) && after != is_word_char(w->text[w->len - 1])) {
                best = w->level;
                if (best == 0) {
                    return 0;
                }
            }
        }
    }
    return best < q->n_levels ? best : -1;
}

/* Sorts all the level words by first byte (a counting sort). */
static void build_level_table(Query *q) {
    int count[256] = {0};
    for (int i = 0; i < q->n_levels; i++) {
        for (int w = 0; w < q->levels[i].n_words; w++) {
            count[q->levels[i].words[w].text[0]]++;
        }
    }
    q->level_start[0] = 0;
    for (int b = 0; b < 256; b++) {
        q->level_start[b + 1] = q->level_start[b] + count[b];
    }
    int fill[256];
    for (int b = 0; b < 256; b++) {
        fill[b] = q->level_start[b];
    }
    for (int i = 0; i < q->n_levels; i++) { /* levels in order: a byte's words stay ordered */
        for (int w = 0; w < q->levels[i].n_words; w++) {
            const Pattern *p = &q->levels[i].words[w];
            q->level_words[fill[p->text[0]]++] = (LevelWord){p->text, p->len, i};
        }
    }
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


#endif

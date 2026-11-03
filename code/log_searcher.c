/*
 * log_searcher.c - LogGrep search engine, version 0.5
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
 *     log_searcher [-i] [-c] [-B] [-m N] [-x EXCLUDE]... [-l LEVEL=WORD,WORD]...
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
 * 2 = error, 3 = a regular expression uses unsupported syntax.
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

/* ---- Regular expressions ------------------------------------------------ */

/* A small regular-expression engine, written from scratch so that the program
 * keeps having no dependencies. It answers one question per line: "does the
 * line contain a match?". Because of that it does not need captures or
 * backtracking: the expression is turned into an NFA and then run as a lazily
 * built DFA (one table lookup per byte, time linear in the size of the text).
 *
 * It understands the part of Python's `re` syntax that is used for searching
 * logs: literals, ., [classes], \d \w \s (and \D \W \S), \b, ^ $ \A \Z,
 * (groups), (?:groups), (?P<name>groups), | and the quantifiers * + ? {m,n}
 * (greedy or lazy). (\B is left to Python: its result on an empty line depends on
 * the Python version.) Anything else (backreferences, lookaround, inline flags,
 * possessive quantifiers...) is reported as unsupported with exit code 3, and
 * loggrep.py then runs the search in Python instead.
 *
 * Semantics match Python's bytes patterns: ASCII classes, case folding of
 * A-Z/a-z only with -i, '.' matches any byte but '\n'. */

#define RE_MAX_PROG 100000   /* NFA instructions */
#define RE_MAX_REPEAT 1000   /* largest {m,n} count */
#define RE_MAX_DEPTH 200     /* nesting of groups */
#define RE_INF (-1)
#ifndef DFA_MAX_STATES
#define DFA_MAX_STATES 4096  /* cached DFA states before the cache is flushed */
#endif
#define DFA_SYMBOLS 257      /* 256 bytes + end of line */
#define DFA_HASH_SIZE (DFA_MAX_STATES * 4)

enum { N_EMPTY, N_SET, N_CAT, N_ALT, N_STAR, N_PLUS, N_QUEST, N_REPEAT, N_ASSERT };
enum { A_BOL, A_EOL, A_WORDB, A_NOTWORDB };
enum { I_SET, I_SPLIT, I_JMP, I_ASSERT, I_MATCH };

typedef struct {
    int type;
    int a;    /* SET: set index; ASSERT: kind; CAT/ALT: first child; others: child */
    int min, max;
    int next; /* next sibling in a CAT/ALT list, -1 if none */
} Node;

typedef struct {
    unsigned char bits[32];
} ByteSet;

typedef struct {
    int op, x, y;
} Inst;

typedef struct {
    const char *s;
    size_t i;
    int icase;
    int depth;
    const char *why; /* set when the expression cannot be handled */
    Node *nodes;
    int n_nodes, cap_nodes;
    ByteSet *sets;
    int n_sets, cap_sets;
} ReParser;

static int re_is_word(unsigned c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int re_fail(ReParser *p, const char *why) {
    if (!p->why) {
        p->why = why;
    }
    return 0;
}

static int re_node(ReParser *p, int type, int a, int min, int max) {
    if (p->n_nodes == p->cap_nodes) {
        int cap = p->cap_nodes ? p->cap_nodes * 2 : 64;
        if (cap > 400000) {
            return re_fail(p, "the regular expression is too complex");
        }
        Node *bigger = realloc(p->nodes, (size_t)cap * sizeof *bigger);
        if (!bigger) {
            return re_fail(p, "out of memory");
        }
        p->nodes = bigger;
        p->cap_nodes = cap;
    }
    Node *n = &p->nodes[p->n_nodes];
    n->type = type;
    n->a = a;
    n->min = min;
    n->max = max;
    n->next = -1;
    return p->n_nodes++;
}

static int re_new_set(ReParser *p) {
    if (p->n_sets == p->cap_sets) {
        int cap = p->cap_sets ? p->cap_sets * 2 : 16;
        if (cap > 400000) {
            return re_fail(p, "the regular expression is too complex");
        }
        ByteSet *bigger = realloc(p->sets, (size_t)cap * sizeof *bigger);
        if (!bigger) {
            return re_fail(p, "out of memory");
        }
        p->sets = bigger;
        p->cap_sets = cap;
    }
    memset(&p->sets[p->n_sets], 0, sizeof(ByteSet));
    return p->n_sets++;
}

static void set_add(ByteSet *s, unsigned c) {
    s->bits[c >> 3] |= (unsigned char)(1u << (c & 7));
}

static int set_has(const ByteSet *s, unsigned c) {
    return (s->bits[c >> 3] >> (c & 7)) & 1;
}

/* cls is 'd', 'w' or 's'; negate selects \D, \W or \S. */
static void set_add_class(ByteSet *s, int cls, int negate) {
    for (unsigned c = 0; c < 256; c++) {
        int in = cls == 'd'   ? (c >= '0' && c <= '9')
                 : cls == 'w' ? re_is_word(c)
                              : (c == ' ' || (c >= 9 && c <= 13));
        if (in != negate) {
            set_add(s, c);
        }
    }
}

static void set_fold_case(ByteSet *s) {
    for (unsigned c = 'a'; c <= 'z'; c++) {
        if (set_has(s, c) || set_has(s, c - 32)) {
            set_add(s, c);
            set_add(s, c - 32);
        }
    }
}

static int re_literal(ReParser *p, unsigned c) {
    int set = re_new_set(p);
    set_add(&p->sets[set], c);
    if (p->icase) {
        set_fold_case(&p->sets[set]);
    }
    return re_node(p, N_SET, set, 0, 0);
}

static int hex_value(int c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
}

/* Reads the two hex digits of \xhh. Returns the byte value or -1. */
static int re_hex_escape(ReParser *p) {
    int hi = hex_value((unsigned char)p->s[p->i]);
    if (hi < 0) {
        return -1;
    }
    int lo = hex_value((unsigned char)p->s[p->i + 1]);
    if (lo < 0) {
        return -1;
    }
    p->i += 2;
    return hi * 16 + lo;
}

static int is_ascii_alnum(unsigned c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int simple_escape_value(int e) {
    switch (e) {
    case 'n': return '\n';
    case 'r': return '\r';
    case 't': return '\t';
    case 'f': return '\f';
    case 'v': return '\v';
    case 'a': return 7;
    default: return -1;
    }
}

/* If a quantifier starts at s, returns its length and fills min/max; else 0.
 * Follows Python: "{" that does not form {m}, {m,}, {,n} or {m,n} is literal. */
static size_t re_quantifier(const char *s, int *min, int *max) {
    if (s[0] == '*') {
        *min = 0;
        *max = RE_INF;
        return 1;
    }
    if (s[0] == '+') {
        *min = 1;
        *max = RE_INF;
        return 1;
    }
    if (s[0] == '?') {
        *min = 0;
        *max = 1;
        return 1;
    }
    if (s[0] != '{' || s[1] == '}') {
        return 0;
    }
    size_t j = 1;
    long lo = 0, hi = 0;
    int has_lo = 0, has_hi = 0, comma = 0;
    while (s[j] >= '0' && s[j] <= '9') {
        lo = lo * 10 + (s[j] - '0');
        if (lo > 1000000) {
            lo = 1000000;
        }
        has_lo = 1;
        j++;
    }
    if (s[j] == ',') {
        comma = 1;
        j++;
        while (s[j] >= '0' && s[j] <= '9') {
            hi = hi * 10 + (s[j] - '0');
            if (hi > 1000000) {
                hi = 1000000;
            }
            has_hi = 1;
            j++;
        }
    }
    if (s[j] != '}') {
        return 0;
    }
    *min = has_lo ? (int)lo : 0;
    *max = comma ? (has_hi ? (int)hi : RE_INF) : *min;
    return j + 1;
}

static int re_parse_alt(ReParser *p);

/* Parses a [...] class; p->i is just after the '['. */
static int re_parse_class(ReParser *p) {
    int negate = 0;
    if (p->s[p->i] == '^') {
        negate = 1;
        p->i++;
    }
    int set_index = re_new_set(p);
    int first = 1;
    for (;;) {
        if (p->why) {
            return 0;
        }
        unsigned char ch = (unsigned char)p->s[p->i];
        if (ch == '\0') {
            return re_fail(p, "unterminated character class");
        }
        p->i++;
        if (ch == ']' && !first) {
            break;
        }
        first = 0;

        int code1 = ch, code1_is_set = 0;
        if (ch == '\\') {
            unsigned char e = (unsigned char)p->s[p->i];
            if (e == '\0') {
                return re_fail(p, "bad escape");
            }
            p->i++;
            if (e == 'd' || e == 'D' || e == 'w' || e == 'W' || e == 's' || e == 'S') {
                char lower = (char)(e | 0x20);
                set_add_class(&p->sets[set_index], lower, e < 'a');
                code1_is_set = 1;
            } else if (e == 'b') {
                code1 = 8;
            } else if (e == 'x') {
                code1 = re_hex_escape(p);
                if (code1 < 0) {
                    return re_fail(p, "bad \\x escape");
                }
            } else if (simple_escape_value(e) >= 0) {
                code1 = simple_escape_value(e);
            } else if (is_ascii_alnum(e)) {
                return re_fail(p, "unsupported escape");
            } else {
                code1 = e;
            }
        }

        if (p->s[p->i] == '-') {
            p->i++;
            unsigned char that = (unsigned char)p->s[p->i];
            if (that == '\0') {
                return re_fail(p, "unterminated character class");
            }
            if (that == ']') { /* the '-' is a literal at the end of the class */
                if (!code1_is_set) {
                    set_add(&p->sets[set_index], (unsigned)code1);
                }
                set_add(&p->sets[set_index], '-');
                continue;
            }
            if (code1_is_set) {
                return re_fail(p, "bad character range");
            }
            p->i++;
            int code2 = that;
            if (that == '\\') {
                unsigned char e = (unsigned char)p->s[p->i];
                if (e == '\0') {
                    return re_fail(p, "bad escape");
                }
                p->i++;
                if (e == 'b') {
                    code2 = 8;
                } else if (e == 'x') {
                    code2 = re_hex_escape(p);
                    if (code2 < 0) {
                        return re_fail(p, "bad \\x escape");
                    }
                } else if (simple_escape_value(e) >= 0) {
                    code2 = simple_escape_value(e);
                } else if (is_ascii_alnum(e)) {
                    return re_fail(p, "unsupported escape or bad character range");
                } else {
                    code2 = e;
                }
            }
            if (code2 < code1) {
                return re_fail(p, "bad character range");
            }
            for (int c = code1; c <= code2; c++) {
                set_add(&p->sets[set_index], (unsigned)c);
            }
        } else if (!code1_is_set) {
            set_add(&p->sets[set_index], (unsigned)code1);
        }
    }

    ByteSet *set = &p->sets[set_index];
    if (p->icase) {
        set_fold_case(set);
    }
    if (negate) {
        for (int i = 0; i < 32; i++) {
            set->bits[i] = (unsigned char)~set->bits[i];
        }
    }
    return re_node(p, N_SET, set_index, 0, 0);
}

static int re_assert(ReParser *p, int kind) {
    return re_node(p, N_ASSERT, kind, 0, 0);
}

/* Parses one atom (a literal, class, group, escape or anchor). */
static int re_parse_atom(ReParser *p) {
    unsigned char c = (unsigned char)p->s[p->i++];
    int min, max;
    switch (c) {
    case '(': {
        if (p->s[p->i] == '?') {
            char kind = p->s[p->i + 1];
            if (kind == ':') {
                p->i += 2;
            } else if (kind == 'P' && p->s[p->i + 2] == '<') {
                size_t j = p->i + 3;
                unsigned char first = (unsigned char)p->s[j];
                if (!(is_ascii_alnum(first) && !(first >= '0' && first <= '9')) && first != '_') {
                    return re_fail(p, "bad group name");
                }
                while (is_ascii_alnum((unsigned char)p->s[j]) || p->s[j] == '_') {
                    j++;
                }
                if (p->s[j] != '>') {
                    return re_fail(p, "bad group name");
                }
                p->i = j + 1;
            } else {
                return re_fail(p, "unsupported group syntax (lookaround, flags, ...)");
            }
        }
        int inner = re_parse_alt(p);
        if (p->why) {
            return 0;
        }
        if (p->s[p->i] != ')') {
            return re_fail(p, "missing )");
        }
        p->i++;
        return re_node(p, N_CAT, inner, 0, 0); /* a group is never an assertion */
    }
    case '[':
        return re_parse_class(p);
    case '.': {
        int set = re_new_set(p);
        for (unsigned b = 0; b < 256; b++) {
            if (b != '\n') {
                set_add(&p->sets[set], b);
            }
        }
        return re_node(p, N_SET, set, 0, 0);
    }
    case '^':
        return re_assert(p, A_BOL);
    case '$':
        return re_assert(p, A_EOL);
    case '*':
    case '+':
    case '?':
        return re_fail(p, "nothing to repeat");
    case '{':
        if (re_quantifier(p->s + p->i - 1, &min, &max)) {
            return re_fail(p, "nothing to repeat");
        }
        return re_literal(p, '{');
    case '\\': {
        unsigned char e = (unsigned char)p->s[p->i];
        if (e == '\0') {
            return re_fail(p, "bad escape at end of pattern");
        }
        p->i++;
        if (e == 'd' || e == 'D' || e == 'w' || e == 'W' || e == 's' || e == 'S') {
            int set = re_new_set(p);
            set_add_class(&p->sets[set], e | 0x20, e < 'a');
            return re_node(p, N_SET, set, 0, 0);
        }
        switch (e) {
        case 'b': return re_assert(p, A_WORDB);
        case 'B': /* matches the empty line only in newer Pythons: leave it to Python */
            return re_fail(p, "\\B is not supported");
        case 'A': return re_assert(p, A_BOL);
        case 'Z': return re_assert(p, A_EOL);
        case 'x': {
            int v = re_hex_escape(p);
            if (v < 0) {
                return re_fail(p, "bad \\x escape");
            }
            return re_literal(p, (unsigned)v);
        }
        default:
            break;
        }
        if (simple_escape_value(e) >= 0) {
            return re_literal(p, (unsigned)simple_escape_value(e));
        }
        if (is_ascii_alnum(e)) {
            return re_fail(p, "unsupported escape (backreference or unknown)");
        }
        return re_literal(p, e);
    }
    default:
        return re_literal(p, c);
    }
}

/* Applies a quantifier, if there is one, to the atom just parsed. */
static int re_parse_quantifier(ReParser *p, int atom) {
    int min, max;
    size_t len = re_quantifier(p->s + p->i, &min, &max);
    if (len == 0) {
        return atom;
    }
    if (p->nodes[atom].type == N_ASSERT) {
        return re_fail(p, "nothing to repeat");
    }
    p->i += len;
    if (p->s[p->i] == '?') { /* lazy: same set of matching lines as greedy */
        p->i++;
    } else if (p->s[p->i] == '+') {
        return re_fail(p, "possessive quantifier");
    }
    int m2, x2;
    if (re_quantifier(p->s + p->i, &m2, &x2)) {
        return re_fail(p, "multiple repeat");
    }
    if (min > RE_MAX_REPEAT || (max != RE_INF && (max > RE_MAX_REPEAT || min > max))) {
        return re_fail(p, "repeat count too large");
    }
    if (min == 0 && max == RE_INF) {
        return re_node(p, N_STAR, atom, 0, RE_INF);
    }
    if (min == 1 && max == RE_INF) {
        return re_node(p, N_PLUS, atom, 1, RE_INF);
    }
    if (min == 0 && max == 1) {
        return re_node(p, N_QUEST, atom, 0, 1);
    }
    return re_node(p, N_REPEAT, atom, min, max);
}

static int re_parse_concat(ReParser *p) {
    int first = -1, last = -1, count = 0;
    while (!p->why) {
        char c = p->s[p->i];
        if (c == '\0' || c == '|' || c == ')') {
            break;
        }
        int atom = re_parse_atom(p);
        if (p->why) {
            break;
        }
        atom = re_parse_quantifier(p, atom);
        if (p->why) {
            break;
        }
        if (first < 0) {
            first = atom;
        } else {
            p->nodes[last].next = atom;
        }
        last = atom;
        count++;
    }
    if (count == 0) {
        return re_node(p, N_EMPTY, 0, 0, 0);
    }
    if (count == 1) {
        return first;
    }
    return re_node(p, N_CAT, first, 0, 0);
}

static int re_parse_alt(ReParser *p) {
    if (++p->depth > RE_MAX_DEPTH) {
        return re_fail(p, "regular expression nested too deeply");
    }
    int first = re_parse_concat(p), last = first, count = 1;
    while (!p->why && p->s[p->i] == '|') {
        p->i++;
        int branch = re_parse_concat(p);
        if (p->why) {
            break;
        }
        p->nodes[last].next = branch;
        last = branch;
        count++;
    }
    p->depth--;
    if (count == 1) {
        return first;
    }
    return re_node(p, N_ALT, first, 0, 0);
}

/* ---- NFA program --------------------------------------------------------- */

typedef struct {
    Inst *code;
    int n, cap;
    const char *why;
} Prog;

static int prog_emit(Prog *pr, int op, int x, int y) {
    if (pr->why) {
        return 0;
    }
    if (pr->n == pr->cap) {
        int cap = pr->cap ? pr->cap * 2 : 64;
        Inst *bigger = realloc(pr->code, (size_t)cap * sizeof *bigger);
        if (!bigger || pr->n >= RE_MAX_PROG) {
            pr->why = "the regular expression is too complex";
            return 0;
        }
        pr->code = bigger;
        pr->cap = cap;
    }
    pr->code[pr->n].op = op;
    pr->code[pr->n].x = x;
    pr->code[pr->n].y = y;
    return pr->n++;
}

static void re_emit(const ReParser *p, Prog *pr, int node) {
    if (pr->why) {
        return;
    }
    const Node *nd = &p->nodes[node];
    switch (nd->type) {
    case N_EMPTY:
        break;
    case N_SET:
        prog_emit(pr, I_SET, nd->a, 0);
        break;
    case N_ASSERT:
        prog_emit(pr, I_ASSERT, nd->a, 0);
        break;
    case N_CAT:
        for (int child = nd->a; child >= 0 && !pr->why; child = p->nodes[child].next) {
            re_emit(p, pr, child);
        }
        break;
    case N_ALT: {
        int branches = 0;
        for (int child = nd->a; child >= 0; child = p->nodes[child].next) {
            branches++;
        }
        int *jumps = malloc((size_t)branches * sizeof *jumps);
        if (!jumps) {
            pr->why = "out of memory";
            break;
        }
        int n_jumps = 0;
        for (int child = nd->a; child >= 0 && !pr->why; child = p->nodes[child].next) {
            int split = -1;
            if (p->nodes[child].next >= 0) {
                split = prog_emit(pr, I_SPLIT, pr->n + 1, 0);
            }
            re_emit(p, pr, child);
            if (split >= 0 && !pr->why) {
                jumps[n_jumps++] = prog_emit(pr, I_JMP, 0, 0);
                pr->code[split].y = pr->n;
            }
        }
        if (!pr->why) {
            for (int k = 0; k < n_jumps; k++) {
                pr->code[jumps[k]].x = pr->n;
            }
        }
        free(jumps);
        break;
    }
    case N_STAR: {
        int split = prog_emit(pr, I_SPLIT, pr->n + 1, 0);
        re_emit(p, pr, nd->a);
        prog_emit(pr, I_JMP, split, 0);
        if (!pr->why) {
            pr->code[split].y = pr->n;
        }
        break;
    }
    case N_PLUS: {
        int start = pr->n;
        re_emit(p, pr, nd->a);
        prog_emit(pr, I_SPLIT, start, pr->n + 1);
        break;
    }
    case N_QUEST: {
        int split = prog_emit(pr, I_SPLIT, pr->n + 1, 0);
        re_emit(p, pr, nd->a);
        if (!pr->why) {
            pr->code[split].y = pr->n;
        }
        break;
    }
    case N_REPEAT: {
        for (int k = 0; k < nd->min && !pr->why; k++) {
            re_emit(p, pr, nd->a);
        }
        if (nd->max == RE_INF) { /* {m,}: m copies, then a* */
            int split = prog_emit(pr, I_SPLIT, pr->n + 1, 0);
            re_emit(p, pr, nd->a);
            prog_emit(pr, I_JMP, split, 0);
            if (!pr->why) {
                pr->code[split].y = pr->n;
            }
        } else { /* {m,n}: n-m nested optional copies */
            int optional = nd->max - nd->min;
            int *splits = optional ? malloc((size_t)optional * sizeof *splits) : NULL;
            if (optional && !splits) {
                pr->why = "out of memory";
                break;
            }
            for (int k = 0; k < optional && !pr->why; k++) {
                splits[k] = prog_emit(pr, I_SPLIT, pr->n + 1, 0);
                re_emit(p, pr, nd->a);
            }
            for (int k = 0; k < optional && !pr->why; k++) {
                pr->code[splits[k]].y = pr->n;
            }
            free(splits);
        }
        break;
    }
    default:
        break;
    }
}

/* ---- Lazy DFA ------------------------------------------------------------ */

/* A DFA state is the set of NFA positions that are still "alive" (before the
 * zero-width assertions among them are resolved, which needs the next byte)
 * plus two bits of context: the previous byte was a word character, and we are
 * at the start of the line. Transitions are computed the first time they are
 * needed and cached. Cached value: 0 = not computed yet, 1 = the line matches,
 * 2 = the line ended without a match, n >= 3 = next state number n - 3. */

#define F_PREVWORD 1u
#define F_START 2u

typedef struct {
    Inst *code;
    int n_code;
    ByteSet *sets;
    int n_states;
    int *state_pcs[DFA_MAX_STATES];
    int state_len[DFA_MAX_STATES];
    unsigned state_flags[DFA_MAX_STATES];
    int *trans;            /* DFA_MAX_STATES * DFA_SYMBOLS */
    int *hash;             /* DFA_HASH_SIZE slots holding state number + 1 */
    unsigned *mark;        /* scratch: visited NFA positions */
    unsigned gen;
    int *stack, *list_a, *list_b;
} Dfa;

static void dfa_expand(Dfa *d, int pc, int *out, int *out_n) {
    int sp = 0;
    d->stack[sp++] = pc;
    while (sp > 0) {
        int at = d->stack[--sp];
        if (d->mark[at] == d->gen) {
            continue;
        }
        d->mark[at] = d->gen;
        const Inst *in = &d->code[at];
        if (in->op == I_JMP) {
            d->stack[sp++] = in->x;
        } else if (in->op == I_SPLIT) {
            d->stack[sp++] = in->y;
            d->stack[sp++] = in->x;
        } else {
            out[(*out_n)++] = at; /* I_SET, I_ASSERT or I_MATCH */
        }
    }
}

static void dfa_new_gen(Dfa *d) {
    if (++d->gen == 0) {
        memset(d->mark, 0, (size_t)d->n_code * sizeof *d->mark);
        d->gen = 1;
    }
}

static void sort_ints(int *a, int n) {
    for (int i = 1; i < n; i++) {
        int v = a[i], j = i - 1;
        while (j >= 0 && a[j] > v) {
            a[j + 1] = a[j];
            j--;
        }
        a[j + 1] = v;
    }
}

static unsigned dfa_hash(const int *pcs, int n, unsigned flags) {
    unsigned h = 2166136261u ^ flags;
    for (int i = 0; i < n; i++) {
        h = (h ^ (unsigned)pcs[i]) * 16777619u;
    }
    return h;
}

static void dfa_reset(Dfa *d) {
    for (int i = 0; i < d->n_states; i++) {
        free(d->state_pcs[i]);
    }
    memset(d->trans, 0, (size_t)d->n_states * DFA_SYMBOLS * sizeof *d->trans);
    memset(d->hash, 0, DFA_HASH_SIZE * sizeof *d->hash);
    d->n_states = 0;
}

/* Returns the number of the state with this content, creating it if needed.
 * If the cache is full it is flushed first and *flushed is set. */
static int dfa_intern(Dfa *d, const int *pcs, int n, unsigned flags, int *flushed) {
    unsigned slot = dfa_hash(pcs, n, flags) & (DFA_HASH_SIZE - 1);
    while (d->hash[slot]) {
        int id = d->hash[slot] - 1;
        if (d->state_len[id] == n && d->state_flags[id] == flags &&
            memcmp(d->state_pcs[id], pcs, (size_t)n * sizeof *pcs) == 0) {
            return id;
        }
        slot = (slot + 1) & (DFA_HASH_SIZE - 1);
    }
    if (d->n_states == DFA_MAX_STATES) {
        /* Flush. State 0 must stay the start state, so rebuild it first. */
        int n_start = 0;
        dfa_new_gen(d);
        dfa_expand(d, 0, d->list_a, &n_start);
        sort_ints(d->list_a, n_start);
        dfa_reset(d);
        int unused = 0;
        dfa_intern(d, d->list_a, n_start, F_START, &unused);
        *flushed = 1;
        return dfa_intern(d, pcs, n, flags, &unused);
    }
    int id = d->n_states++;
    d->state_pcs[id] = malloc((size_t)(n ? n : 1) * sizeof *pcs);
    if (!d->state_pcs[id]) {
        fputs("Error: out of memory.\n", stderr);
        exit(2);
    }
    memcpy(d->state_pcs[id], pcs, (size_t)n * sizeof *pcs);
    d->state_len[id] = n;
    d->state_flags[id] = flags;
    slot = dfa_hash(pcs, n, flags) & (DFA_HASH_SIZE - 1);
    while (d->hash[slot]) {
        slot = (slot + 1) & (DFA_HASH_SIZE - 1);
    }
    d->hash[slot] = id + 1;
    return id;
}

/* Computes (and caches) the transition of state 'sid' on 'sym' (a byte, or 256
 * for the end of the line). Returns the cached-value encoding. */
static int dfa_compute(Dfa *d, int sid, int sym) {
    unsigned flags = d->state_flags[sid];
    int prev_word = (flags & F_PREVWORD) != 0;
    int at_start = (flags & F_START) != 0;
    int at_end = sym == 256;
    int next_word = !at_end && re_is_word((unsigned)sym);

    /* 1. Resolve the zero-width assertions with the context we now know. */
    int rn = 0;
    int *reach = d->list_a;
    dfa_new_gen(d);
    for (int k = 0; k < d->state_len[sid]; k++) {
        int pc = d->state_pcs[sid][k];
        d->mark[pc] = d->gen;
        reach[rn++] = pc;
    }
    int matched = 0;
    for (int k = 0; k < rn; k++) {
        const Inst *in = &d->code[reach[k]];
        if (in->op == I_MATCH) {
            matched = 1;
        } else if (in->op == I_ASSERT) {
            int holds = in->x == A_BOL          ? at_start
                        : in->x == A_EOL        ? at_end
                        : in->x == A_WORDB      ? prev_word != next_word
                                                : prev_word == next_word;
            if (holds) {
                dfa_expand(d, reach[k] + 1, reach, &rn);
            }
        }
    }

    int result;
    if (matched) {
        result = 1;
    } else if (at_end) {
        result = 2;
    } else {
        /* 2. Step over the byte; a new match attempt also starts after it. */
        int nn = 0;
        int *next = d->list_b;
        dfa_new_gen(d);
        for (int k = 0; k < rn; k++) {
            const Inst *in = &d->code[reach[k]];
            if (in->op == I_SET && set_has(&d->sets[in->x], (unsigned)sym)) {
                dfa_expand(d, reach[k] + 1, next, &nn);
            }
        }
        dfa_expand(d, 0, next, &nn);
        sort_ints(next, nn);
        int flushed = 0;
        int id = dfa_intern(d, next, nn, next_word ? F_PREVWORD : 0, &flushed);
        if (flushed) {
            return id + 3; /* the old state number is gone: do not cache */
        }
        result = id + 3;
    }
    d->trans[(size_t)sid * DFA_SYMBOLS + (size_t)sym] = result;
    return result;
}

static void dfa_free(Dfa *d) {
    if (!d) {
        return;
    }
    for (int i = 0; i < d->n_states; i++) {
        free(d->state_pcs[i]);
    }
    free(d->code);
    free(d->sets);
    free(d->trans);
    free(d->hash);
    free(d->mark);
    free(d->stack);
    free(d->list_a);
    free(d->list_b);
    free(d);
}

/* Compiles the expressions (a line matches if ANY of them matches). Returns
 * NULL and sets *why if they cannot be handled. */
static Dfa *dfa_build(const char *const *regexes, int n, int icase, const char **why) {
    ReParser p;
    memset(&p, 0, sizeof p);
    p.icase = icase;
    re_node(&p, N_EMPTY, 0, 0, 0); /* node 0: harmless target for errors */
    re_new_set(&p);                /* set 0 likewise */

    int first = -1, last = -1;
    for (int k = 0; k < n && !p.why; k++) {
        p.s = regexes[k];
        p.i = 0;
        p.depth = 0;
        int root = re_parse_alt(&p);
        if (!p.why && p.s[p.i] != '\0') {
            re_fail(&p, "unbalanced parenthesis");
        }
        if (p.why) {
            break;
        }
        if (first < 0) {
            first = root;
        } else {
            p.nodes[last].next = root;
        }
        last = root;
    }
    int top = 0;
    if (!p.why) {
        top = n > 1 ? re_node(&p, N_ALT, first, 0, 0) : first;
    }

    Prog pr;
    memset(&pr, 0, sizeof pr);
    if (!p.why) {
        re_emit(&p, &pr, top);
        prog_emit(&pr, I_MATCH, 0, 0);
        if (pr.why) {
            re_fail(&p, pr.why);
        }
    }
    if (p.why) {
        *why = p.why;
        free(p.nodes);
        free(p.sets);
        free(pr.code);
        return NULL;
    }

    Dfa *d = calloc(1, sizeof *d);
    if (d) {
        d->code = pr.code;
        d->n_code = pr.n;
        d->sets = p.sets;
        d->trans = calloc((size_t)DFA_MAX_STATES * DFA_SYMBOLS, sizeof *d->trans);
        d->hash = calloc(DFA_HASH_SIZE, sizeof *d->hash);
        d->mark = calloc((size_t)pr.n, sizeof *d->mark);
        d->stack = malloc((size_t)(2 * pr.n + 2) * sizeof *d->stack);
        d->list_a = malloc((size_t)(pr.n + 1) * sizeof *d->list_a);
        d->list_b = malloc((size_t)(pr.n + 1) * sizeof *d->list_b);
    }
    free(p.nodes);
    if (!d || !d->trans || !d->hash || !d->mark || !d->stack || !d->list_a || !d->list_b) {
        *why = "out of memory";
        dfa_free(d);
        if (!d) {
            free(p.sets);
            free(pr.code);
        }
        return NULL;
    }

    int n_start = 0, flushed = 0;
    dfa_new_gen(d);
    dfa_expand(d, 0, d->list_a, &n_start);
    sort_ints(d->list_a, n_start);
    dfa_intern(d, d->list_a, n_start, F_START, &flushed); /* state 0 */
    return d;
}

/* True if the line (without its line ending) contains a match. */
static int dfa_search(Dfa *d, const unsigned char *line, size_t len) {
    const int *trans = d->trans;
    int row = 0; /* state number * DFA_SYMBOLS */
    for (size_t i = 0; i < len; i++) {
        int t = trans[row + line[i]];
        if (t < 3) {
            if (t == 0) {
                t = dfa_compute(d, row / DFA_SYMBOLS, line[i]);
            }
            if (t == 1) {
                return 1;
            }
        }
        row = (t - 3) * DFA_SYMBOLS;
    }
    int t = trans[row + 256];
    if (t == 0) {
        t = dfa_compute(d, row / DFA_SYMBOLS, 256);
    }
    return t == 1;
}

enum { FMT_NONE = 0, FMT_TXT, FMT_CSV, FMT_JSON };

typedef struct {
    Pattern include[MAX_PATTERNS];
    int n_include;
    Pattern exclude[MAX_PATTERNS];
    int n_exclude;
    Dfa *dfa;  /* all -r expressions compiled together, NULL if there are none */
    int n_regex;
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
    if (!hit && q->dfa) {
        hit = dfa_search(q->dfa, line, len);
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
        RegionResult r = dense || q->dfa ? scan_region_lines(q, data + pos, end - pos, lines + 1, &matches)
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
          "[-o OUTFILE -F txt|csv|json [-s SEVERITY]] [-e PATTERN]... [-r REGEX]... FILE\n"
          "       log_searcher [-i] -k -r REGEX [-r REGEX]...\n",
          stderr);
}

int main(int argc, char **argv) {
    Query *q = &query;
    int ignore_case = 0;
    const char *include_args[MAX_PATTERNS];
    const char *exclude_args[MAX_PATTERNS];
    const char *regex_args[MAX_PATTERNS];
    int check_only = 0;
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
        } else if (strcmp(argv[i], "-k") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            if (q->n_regex == MAX_PATTERNS) {
                fputs("Error: too many -r expressions.\n", stderr);
                return 2;
            }
            regex_args[q->n_regex++] = argv[++i];
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

    if (check_only ? q->n_regex == 0 : (!path || q->n_include + q->n_regex == 0)) {
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

    if (q->n_regex) {
        const char *why = NULL;
        q->dfa = dfa_build(regex_args, q->n_regex, ignore_case, &why);
        if (!q->dfa) {
            fprintf(stderr, "Error: unsupported regular expression: %s.\n", why ? why : "unknown");
            return 3;
        }
    }
    if (check_only) {
        return 0;
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

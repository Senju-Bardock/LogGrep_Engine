/* lg_regex.h - regular-expression engine (parser, NFA, required literals, lazy DFA).
 * Self-contained: it knows nothing about files, lines or levels. */
#ifndef LG_REGEX_H
#define LG_REGEX_H

#include "lg_platform.h"

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

/* ---- Required literals --------------------------------------------------- */

/* Most useful regular expressions contain some fixed text that every match
 * must include, e.g. "Failed password" in "Failed password|Invalid user" or
 * "ERROR" in "^\d+ ERROR .*". lit_info() works out, for every part of the
 * expression, either the exact set of strings it can match or a set of strings
 * of which at least one must appear in anything it matches. The search then
 * looks for those strings with the fast literal search and only runs the DFA
 * on the lines that contain one. With -i the strings are lower-cased and are
 * compared case-insensitively. The sets are always a superset of the truth, so
 * no matching line is ever skipped. */

#define LIT_MAX 12        /* strings per set */
#define LIT_LEN 32        /* longest string kept */
#define LIT_MIN_USEFUL 3  /* shorter strings are too common to be worth it */
#define LIT_DEPTH 24      /* deeper parts of the expression are not analysed */

typedef struct {
    int n;
    int len[LIT_MAX];
    unsigned char s[LIT_MAX][LIT_LEN];
} LitSet;

typedef struct {
    int exact;   /* the part can only match the strings in 'ex' */
    LitSet ex;
    LitSet must; /* otherwise: a match contains one of these (n == 0: unknown) */
} LitInfo;

static int lit_add(LitSet *set, const unsigned char *str, int len) {
    if (len > LIT_LEN) {
        return 0;
    }
    for (int i = 0; i < set->n; i++) {
        if (set->len[i] == len && memcmp(set->s[i], str, (size_t)len) == 0) {
            return 1;
        }
    }
    if (set->n == LIT_MAX) {
        return 0;
    }
    memcpy(set->s[set->n], str, (size_t)len);
    set->len[set->n] = len;
    set->n++;
    return 1;
}

static int lit_has_empty(const LitSet *set) {
    for (int i = 0; i < set->n; i++) {
        if (set->len[i] == 0) {
            return 1;
        }
    }
    return 0;
}

/* out = every concatenation of a string of a with a string of b. 0 if it does not fit. */
static int lit_product(const LitSet *a, const LitSet *b, LitSet *out) {
    out->n = 0;
    for (int i = 0; i < a->n; i++) {
        for (int j = 0; j < b->n; j++) {
            unsigned char buf[2 * LIT_LEN];
            int len = a->len[i] + b->len[j];
            if (len > LIT_LEN) {
                return 0;
            }
            memcpy(buf, a->s[i], (size_t)a->len[i]);
            memcpy(buf + a->len[i], b->s[j], (size_t)b->len[j]);
            if (!lit_add(out, buf, len)) {
                return 0;
            }
        }
    }
    return 1;
}

static int lit_union(LitSet *dst, const LitSet *src) {
    for (int i = 0; i < src->n; i++) {
        if (!lit_add(dst, src->s[i], src->len[i])) {
            return 0;
        }
    }
    return 1;
}

/* The strings of which one must appear in any match of this part, or NULL. */
static const LitSet *lit_usable(const LitInfo *info) {
    if (info->exact) {
        return lit_has_empty(&info->ex) ? NULL : &info->ex;
    }
    return info->must.n ? &info->must : NULL;
}

/* Keeps the best candidate: the one whose shortest string is longest. */
static void lit_consider(LitSet *best, int *best_score, const LitSet *candidate) {
    if (!candidate || candidate->n == 0 || lit_has_empty(candidate)) {
        return;
    }
    int shortest = LIT_LEN + 1;
    for (int i = 0; i < candidate->n; i++) {
        if (candidate->len[i] < shortest) {
            shortest = candidate->len[i];
        }
    }
    int score = shortest * 100 - candidate->n;
    if (score > *best_score) {
        *best = *candidate;
        *best_score = score;
    }
}

static void lit_info(const ReParser *p, int node, int icase, int depth, LitInfo *out) {
    memset(out, 0, sizeof *out);
    if (depth > LIT_DEPTH) {
        return; /* no information: always safe */
    }
    const Node *nd = &p->nodes[node];
    switch (nd->type) {
    case N_EMPTY:
    case N_ASSERT: /* zero width: it only restricts, so the empty string is a superset */
        out->exact = 1;
        lit_add(&out->ex, (const unsigned char *)"", 0);
        break;
    case N_SET: {
        unsigned char seen[256] = {0}, folded[5];
        int count = 0;
        for (unsigned b = 0; b < 256; b++) {
            if (!set_has(&p->sets[nd->a], b)) {
                continue;
            }
            unsigned char f = (unsigned char)(icase ? tolower((int)b) : (int)b);
            if (!seen[f]) {
                seen[f] = 1;
                if (count < 5) {
                    folded[count] = f;
                }
                count++;
            }
        }
        if (count >= 1 && count <= 4) {
            out->exact = 1;
            for (int i = 0; i < count; i++) {
                lit_add(&out->ex, &folded[i], 1);
            }
        }
        break;
    }
    case N_CAT: {
        LitSet acc, best;
        int best_score = -1, whole_exact = 1;
        acc.n = 0;
        lit_add(&acc, (const unsigned char *)"", 0);
        best.n = 0;
        for (int child = nd->a; child >= 0; child = p->nodes[child].next) {
            LitInfo ci;
            lit_info(p, child, icase, depth + 1, &ci);
            if (ci.exact) {
                LitSet product;
                if (lit_product(&acc, &ci.ex, &product)) {
                    acc = product;
                } else { /* too many or too long: keep what we have and start again */
                    whole_exact = 0;
                    lit_consider(&best, &best_score, &acc);
                    acc = ci.ex;
                }
            } else {
                whole_exact = 0;
                lit_consider(&best, &best_score, &acc);
                acc.n = 0;
                lit_add(&acc, (const unsigned char *)"", 0);
                lit_consider(&best, &best_score, ci.must.n ? &ci.must : NULL);
            }
        }
        if (whole_exact) {
            out->exact = 1;
            out->ex = acc;
        } else {
            lit_consider(&best, &best_score, &acc);
            out->must = best;
        }
        break;
    }
    case N_ALT: {
        LitSet exact_union, must_union;
        int all_exact = 1, must_ok = 1;
        exact_union.n = 0;
        must_union.n = 0;
        for (int child = nd->a; child >= 0; child = p->nodes[child].next) {
            LitInfo ci;
            lit_info(p, child, icase, depth + 1, &ci);
            if (all_exact && (!ci.exact || !lit_union(&exact_union, &ci.ex))) {
                all_exact = 0;
            }
            const LitSet *usable = lit_usable(&ci);
            if (must_ok && (!usable || !lit_union(&must_union, usable))) {
                must_ok = 0;
            }
        }
        if (all_exact) {
            out->exact = 1;
            out->ex = exact_union;
        } else if (must_ok) {
            out->must = must_union;
        }
        break;
    }
    case N_QUEST: {
        LitInfo ci;
        lit_info(p, nd->a, icase, depth + 1, &ci);
        if (ci.exact) { /* the child, or nothing */
            out->exact = 1;
            out->ex = ci.ex;
            if (!lit_add(&out->ex, (const unsigned char *)"", 0)) {
                out->exact = 0;
            }
        }
        break;
    }
    case N_PLUS:
    case N_REPEAT:
        if (nd->type == N_PLUS || nd->min >= 1) { /* at least one copy of the child is there */
            LitInfo ci;
            lit_info(p, nd->a, icase, depth + 1, &ci);
            const LitSet *usable = lit_usable(&ci);
            if (usable) {
                out->must = *usable;
            }
        }
        break;
    default: /* N_STAR: may match nothing */
        break;
    }
}

/* Chooses the strings to search for before running the DFA, if there are good
 * ones. Returns 1 and fills 'out' when every match must contain one of them. */
static int lit_pick_prefilter(const ReParser *p, int top, int icase, LitSet *out) {
    LitInfo info;
    lit_info(p, top, icase, 0, &info);
    const LitSet *usable = lit_usable(&info);
    if (!usable || usable->n == 0) {
        return 0;
    }
    for (int i = 0; i < usable->n; i++) {
        if (usable->len[i] < LIT_MIN_USEFUL || memchr(usable->s[i], '\n', (size_t)usable->len[i])) {
            return 0;
        }
    }
    *out = *usable;
    return 1;
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
    LitSet prefilter;      /* strings of which every match contains one */
    int has_prefilter;
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
    if (d) {
        d->has_prefilter = lit_pick_prefilter(&p, top, icase, &d->prefilter);
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


#endif

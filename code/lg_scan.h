/* lg_scan.h - scanning a file: line by line, mapped, and in parallel. */
#ifndef LG_SCAN_H
#define LG_SCAN_H

#include "lg_query.h"
#include "lg_export.h"
#include "lg_thread.h"

/* One match found by a worker thread, waiting for the main thread to write it. */
typedef struct {
    const unsigned char *line; /* points into the mapped file */
    size_t len;
    unsigned long long rel_line; /* line number inside the chunk, starting at 1 */
    int level;
} Record;

/* Everything one thread needs to scan: its own automaton, counters and, when it
 * is a worker, the list of matches it has found. */
typedef struct {
    const Query *q;
    Dfa *dfa;
    Counters count;
    Exporter *exporter; /* direct mode: matches are written at once */
    int record;         /* worker mode: matches are kept as Records instead */
    int keep;           /* ...but only if somebody will print or export them */
    Record *rec;
    size_t n_rec, cap_rec;
    int can_skip; /* the chunk scan can jump from match to match */
    int dense;    /* the previous chunk had many matches */
    int hold;     /* chunks left to read line by line before trying to skip again */
} Scanner;

static void scanner_init(Scanner *sc, const Query *q, Dfa *dfa, Exporter *exporter, int record, int keep) {
    memset(sc, 0, sizeof *sc);
    sc->q = q;
    sc->dfa = dfa;
    sc->exporter = exporter;
    sc->record = record;
    sc->keep = keep;
    /* Without a literal every line must go through the DFA anyway. */
    sc->can_skip = q->n_cand > 0 && (q->n_regex == 0 || q->n_prefilter > 0);
}

/* Writes one match to stdout and to the export file. Returns 1 if stdout failed. */
static int emit_match(const Query *q, Exporter *ex, unsigned long long line_no, const unsigned char *line,
                      size_t len, int level) {
    if (ex && ex->fp) {
        export_match(ex, line_no, level >= 0 ? q->levels[level].name : ex->fallback_level, line, len);
    }
    if (!q->count_only) {
        if (q->console) { /* the exact text loggrep.py prints without colours */
            const char *shown = level >= 0 ? q->levels[level].name : (ex ? ex->fallback_level : NULL);
            size_t n;
            const unsigned char *text = utf8_clean(line, len, &n);
            printf("%9llu | ", line_no);
            if (shown) {
                printf("[%s] ", shown);
            }
            fwrite(text, 1, n, stdout);
#ifdef _WIN32
            fputs("\r\n", stdout); /* what Python's print writes on Windows */
#else
            fputc('\n', stdout);
#endif
            if (ferror(stdout)) {
                return 1;
            }
            return 0;
        }
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
    return 0;
}

/* Handles one line: if it matches, counts it and writes it (or keeps it for the
 * main thread). Returns 1 when the search must stop. */
static int scanner_line(Scanner *sc, unsigned long long line_no, const unsigned char *line, size_t len) {
    const Query *q = sc->q;
    if (!line_matches(q, sc->dfa, line, len)) {
        return 0;
    }
    sc->count.matches++;
    int level = q->n_levels ? classify(q, line, len) : -1;
    if (level >= 0) {
        sc->count.level[level]++;
    } else {
        sc->count.unclassified++;
    }

    if (sc->record) {
        if (sc->keep) {
            if (sc->n_rec == sc->cap_rec) {
                size_t cap = sc->cap_rec ? sc->cap_rec * 2 : 256;
                Record *bigger = realloc(sc->rec, cap * sizeof *bigger);
                if (!bigger) {
                    fputs("Error: out of memory.\n", stderr);
                    exit(2);
                }
                sc->rec = bigger;
                sc->cap_rec = cap;
            }
            Record *r = &sc->rec[sc->n_rec++];
            r->line = line;
            r->len = len;
            r->rel_line = line_no;
            r->level = level;
        }
        return 0;
    }
    if (emit_match(q, sc->exporter, line_no, line, len, level)) {
        return 1;
    }
    return q->max_matches && sc->count.matches >= q->max_matches;
}

/* Reads the file in blocks and checks it line by line. Returns -1 on error. */
static int scan_buffered(Scanner *sc, FILE *f, unsigned long long *lines_out,
                         unsigned long long *consumed_out) {
    size_t cap = BLOCK_SIZE;
    size_t have = 0; /* bytes currently held in buf */
    unsigned char *buf = malloc(cap);
    if (!buf) {
        fputs("Error: out of memory.\n", stderr);
        return -1;
    }

    unsigned long long line_no = 0, consumed = 0;
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
            if (scanner_line(sc, line_no, buf + start, len)) {
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
        scanner_line(sc, line_no, buf, len);
    }

    free(buf);
    *lines_out = line_no;
    *consumed_out = consumed;
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

typedef struct {
    unsigned long long lines;      /* lines covered (up to the last one handled when stopped) */
    size_t consumed;               /* bytes covered */
    int stop;                      /* the search must end */
    unsigned long long candidates; /* lines that had to be examined */
} RegionResult;

/* Searches a region that starts at the beginning of a line and ends at the end
 * of a line (or of the file). Instead of visiting every line, it looks for the
 * patterns in the raw bytes, jumps to the line that contains the first
 * occurrence, checks it and continues after it. Patterns contain no newline,
 * so no match can span two lines. */
static RegionResult scan_region(Scanner *sc, const unsigned char *data, size_t size,
                                unsigned long long first_line_no) {
    const Query *q = sc->q;
    RegionResult r = {0, 0, 0, 0};
    size_t next[MAX_PATTERNS + LIT_MAX]; /* next occurrence of each candidate at or after 'cursor' */
    for (int i = 0; i < q->n_cand; i++) {
        next[i] = UNKNOWN;
    }
    size_t cursor = 0;                   /* start of the first line not handled yet */
    unsigned long long lines_before = 0; /* lines before 'cursor' */

    while (cursor < size) {
        size_t best = NOT_FOUND;
        for (int i = 0; i < q->n_cand; i++) {
            if (next[i] == NOT_FOUND) {
                continue; /* this pattern does not occur any more */
            }
            if (next[i] == UNKNOWN || next[i] < cursor) {
                next[i] = pattern_find_fast(q->cand[i], data, size, cursor);
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

        int stop = scanner_line(sc, first_line_no + lines_before, data + ls, len);
        r.candidates++;
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
static RegionResult scan_region_lines(Scanner *sc, const unsigned char *data, size_t size,
                                      unsigned long long first_line_no) {
    RegionResult r = {0, 0, 0, 0};
    size_t start = 0;
    unsigned long long lines_before = 0;

    while (start < size) {
        const unsigned char *nl = memchr(data + start, '\n', size - start);
        size_t end = nl ? (size_t)(nl - data) : size;
        size_t len = end - start;
        while (len > 0 && data[start + len - 1] == '\r') { /* CRLF, like Python's rstrip */
            len--;
        }
        int stop = scanner_line(sc, first_line_no + lines_before, data + start, len);
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

/* Searches one chunk the way that suits the density of matches seen in the
 * previous one: jumping between matches when they are sparse, line by line when
 * more than a third of the lines match. */
static RegionResult scan_chunk(Scanner *sc, const unsigned char *data, size_t size,
                               unsigned long long first_line_no) {
    unsigned long long matches_before = sc->count.matches;
    int by_lines = !sc->can_skip || sc->dense || sc->hold > 0;
    RegionResult r = by_lines ? scan_region_lines(sc, data, size, first_line_no)
                              : scan_region(sc, data, size, first_line_no);
    if (sc->hold > 0) {
        sc->hold--;
    }
    /* In region mode we know how many lines had to be examined; reading line
     * by line all we know is how many matched. */
    unsigned long long busy = by_lines ? sc->count.matches - matches_before : r.candidates;
    sc->dense = r.lines > 0 && busy * 3 > r.lines;
    if (!by_lines && sc->dense) {
        sc->hold = 3; /* the prefilter is not selective here: do not flip every chunk */
    }
    return r;
}

/* The mapped file is cut into chunks of about MAP_CHUNK bytes; every chunk
 * starts at the beginning of a line. Chunk i starts at the first line start at or
 * after i * MAP_CHUNK. */
static size_t chunk_count(size_t size) {
    return (size + MAP_CHUNK - 1) / MAP_CHUNK;
}

static size_t chunk_start(const unsigned char *data, size_t size, size_t i) {
    if (i == 0) {
        return 0;
    }
    size_t x = i * MAP_CHUNK;
    if (x >= size) {
        return size;
    }
    const unsigned char *nl = memchr(data + x - 1, '\n', size - (x - 1));
    return nl ? (size_t)(nl - data) + 1 : size;
}

/* Looks at the byte frequencies of the start of the file and, for each string
 * the chunk scan will look for, picks its rarest byte (see pattern_find_fast). */
static void prepare_mapped(Query *q, const unsigned char *data, size_t size) {
    unsigned long long freq[256] = {0};
    size_t sample = size < ((size_t)1 << 20) ? size : ((size_t)1 << 20);
    for (size_t i = 0; i < sample; i++) {
        freq[data[i]]++;
    }
    for (int i = 0; i < q->n_cand; i++) {
        pattern_pick_rare(q->cand[i], freq);
    }
}

/* Searches a whole mapped file on the calling thread, one chunk at a time. */
static void scan_mapped(Scanner *sc, const unsigned char *data, size_t size, unsigned long long *lines_out,
                        unsigned long long *consumed_out) {
    unsigned long long lines = 0;
    size_t consumed = 0;
    int stop = 0;
    size_t chunks = chunk_count(size);

    for (size_t i = 0; i < chunks && !stop; i++) {
        size_t start = chunk_start(data, size, i), end = chunk_start(data, size, i + 1);
        if (end == start) {
            continue;
        }
        RegionResult r = scan_chunk(sc, data + start, end - start, lines + 1);
        lines += r.lines;
        consumed = start + r.consumed;
        stop = r.stop;
    }
    if (!stop) {
        consumed = size;
    }
    *lines_out = lines;
    *consumed_out = consumed;
}

/* ---- Parallel scan -------------------------------------------------------- */

/* Worker threads search chunks and hand back, for each chunk, its counters and
 * the list of matches with line numbers relative to the chunk. The main thread
 * (the "director") takes the chunks in file order, turns the relative line
 * numbers into real ones and writes everything, so the output is exactly what
 * a single thread would have produced. At most 'window' chunks are in flight, so
 * memory stays bounded. */

typedef struct {
    int ready;
    unsigned long long lines;
    Counters count;
    Record *rec;
    size_t n_rec;
} Slot;

typedef struct {
    const Query *q;
    const unsigned char *data;
    size_t size, chunks;
    int window;
    int keep; /* the matches will be printed or exported */
    LgMutex mu;
    LgCond cv;
    size_t next;     /* next chunk to hand out */
    size_t consumed; /* chunks the director has taken */
    int stop;
    Slot *slots;
} Shared;

static void worker_main(void *arg) {
    Shared *sh = arg;
    const Query *q = sh->q;
    Dfa *dfa = NULL;
    if (q->n_regex) { /* each thread needs its own: the automaton changes as it learns */
        const char *why = NULL;
        dfa = dfa_build(q->regex_args, q->n_regex, q->ignore_case, &why);
        if (!dfa) {
            fputs("Error: could not build the regular expression.\n", stderr);
            exit(2);
        }
    }
    Scanner sc;
    scanner_init(&sc, q, dfa, NULL, 1, sh->keep);

    for (;;) {
        lg_mutex_lock(&sh->mu);
        while (!sh->stop && sh->next < sh->chunks && sh->next >= sh->consumed + (size_t)sh->window) {
            lg_cond_wait(&sh->cv, &sh->mu);
        }
        if (sh->stop || sh->next >= sh->chunks) {
            lg_mutex_unlock(&sh->mu);
            break;
        }
        size_t i = sh->next++;
        lg_mutex_unlock(&sh->mu);

        size_t start = chunk_start(sh->data, sh->size, i), end = chunk_start(sh->data, sh->size, i + 1);
        memset(&sc.count, 0, sizeof sc.count);
        sc.rec = NULL;
        sc.n_rec = sc.cap_rec = 0;
        unsigned long long lines = 0;
        if (end > start) {
            lines = scan_chunk(&sc, sh->data + start, end - start, 1).lines;
        }

        lg_mutex_lock(&sh->mu);
        Slot *slot = &sh->slots[i % (size_t)sh->window];
        slot->lines = lines;
        slot->count = sc.count;
        slot->rec = sc.rec;
        slot->n_rec = sc.n_rec;
        slot->ready = 1;
        lg_cond_broadcast(&sh->cv);
        lg_mutex_unlock(&sh->mu);
    }
    dfa_free(dfa);
}

/* Searches a whole mapped file with 'threads' worker threads. Returns the lines
 * of the file and the totals, and 1 in *failed if writing to stdout failed. */
static void scan_mapped_parallel(Query *q, Exporter *ex, const unsigned char *data, size_t size, int threads,
                                 unsigned long long *lines_out, Counters *total, int *failed) {
    Shared sh;
    memset(&sh, 0, sizeof sh);
    sh.q = q;
    sh.data = data;
    sh.size = size;
    sh.chunks = chunk_count(size);
    sh.window = threads + 2;
    sh.keep = !q->count_only || (ex && ex->fp);
    sh.slots = calloc((size_t)sh.window, sizeof *sh.slots);
    LgThread *pool = calloc((size_t)threads, sizeof *pool);
    if (!sh.slots || !pool) {
        fputs("Error: out of memory.\n", stderr);
        exit(2);
    }
    lg_mutex_init(&sh.mu);
    lg_cond_init(&sh.cv);

    int started = 0;
    for (int t = 0; t < threads; t++) {
        if (lg_thread_start(&pool[started], worker_main, &sh) == 0) {
            started++;
        }
    }
    if (started == 0) { /* could not create any thread: do the work here */
        Scanner sc;
        scanner_init(&sc, q, q->dfa, ex, 0, 0);
        unsigned long long consumed;
        scan_mapped(&sc, data, size, lines_out, &consumed);
        *total = sc.count;
        free(pool);
        free(sh.slots);
        lg_mutex_destroy(&sh.mu);
        lg_cond_destroy(&sh.cv);
        return;
    }

    unsigned long long lines_done = 0;
    int stop = 0;
    for (size_t i = 0; i < sh.chunks && !stop; i++) {
        Slot slot;
        lg_mutex_lock(&sh.mu);
        while (!sh.slots[i % (size_t)sh.window].ready) {
            lg_cond_wait(&sh.cv, &sh.mu);
        }
        slot = sh.slots[i % (size_t)sh.window];
        sh.slots[i % (size_t)sh.window].ready = 0;
        sh.consumed = i + 1;
        lg_cond_broadcast(&sh.cv);
        lg_mutex_unlock(&sh.mu);

        for (size_t k = 0; k < slot.n_rec && !stop; k++) {
            const Record *r = &slot.rec[k];
            stop = emit_match(q, ex, lines_done + r->rel_line, r->line, r->len, r->level);
        }
        counters_add(total, &slot.count);
        lines_done += slot.lines;
        free(slot.rec);
    }

    lg_mutex_lock(&sh.mu);
    sh.stop = 1;
    lg_cond_broadcast(&sh.cv);
    lg_mutex_unlock(&sh.mu);
    for (int t = 0; t < started; t++) {
        lg_thread_join(&pool[t]);
    }
    for (int s = 0; s < sh.window; s++) { /* chunks finished but never taken */
        if (sh.slots[s].ready) {
            free(sh.slots[s].rec);
        }
    }
    free(pool);
    free(sh.slots);
    lg_mutex_destroy(&sh.mu);
    lg_cond_destroy(&sh.cv);
    *lines_out = lines_done;
    *failed = stop;
}


#endif

/* lg_thread.h - the little bit of threading the program needs: start/join a
 * thread, a mutex, a condition variable and the number of CPU cores. Win32
 * threads on Windows, pthreads elsewhere (compile with -pthread there). */
#ifndef LG_THREAD_H
#define LG_THREAD_H

#include "lg_platform.h"

typedef struct {
    void (*fn)(void *);
    void *arg;
} LgThreadStart;

#ifdef _WIN32

typedef HANDLE LgThread;
typedef CRITICAL_SECTION LgMutex;
typedef CONDITION_VARIABLE LgCond;

static DWORD WINAPI lg_thread_entry(LPVOID p) {
    LgThreadStart start = *(LgThreadStart *)p;
    free(p);
    start.fn(start.arg);
    return 0;
}

static int lg_thread_start(LgThread *t, void (*fn)(void *), void *arg) {
    LgThreadStart *start = malloc(sizeof *start);
    if (!start) {
        return -1;
    }
    start->fn = fn;
    start->arg = arg;
    *t = CreateThread(NULL, 0, lg_thread_entry, start, 0, NULL);
    if (!*t) {
        free(start);
        return -1;
    }
    return 0;
}

static void lg_thread_join(LgThread *t) {
    WaitForSingleObject(*t, INFINITE);
    CloseHandle(*t);
}

static void lg_mutex_init(LgMutex *m) { InitializeCriticalSection(m); }
static void lg_mutex_destroy(LgMutex *m) { DeleteCriticalSection(m); }
static void lg_mutex_lock(LgMutex *m) { EnterCriticalSection(m); }
static void lg_mutex_unlock(LgMutex *m) { LeaveCriticalSection(m); }
static void lg_cond_init(LgCond *c) { InitializeConditionVariable(c); }
static void lg_cond_destroy(LgCond *c) { (void)c; }
static void lg_cond_wait(LgCond *c, LgMutex *m) { SleepConditionVariableCS(c, m, INFINITE); }
static void lg_cond_broadcast(LgCond *c) { WakeAllConditionVariable(c); }

static int lg_cpu_count(void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors > 0 ? (int)info.dwNumberOfProcessors : 1;
}

#else

typedef pthread_t LgThread;
typedef pthread_mutex_t LgMutex;
typedef pthread_cond_t LgCond;

static void *lg_thread_entry(void *p) {
    LgThreadStart start = *(LgThreadStart *)p;
    free(p);
    start.fn(start.arg);
    return NULL;
}

static int lg_thread_start(LgThread *t, void (*fn)(void *), void *arg) {
    LgThreadStart *start = malloc(sizeof *start);
    if (!start) {
        return -1;
    }
    start->fn = fn;
    start->arg = arg;
    if (pthread_create(t, NULL, lg_thread_entry, start) != 0) {
        free(start);
        return -1;
    }
    return 0;
}

static void lg_thread_join(LgThread *t) { pthread_join(*t, NULL); }
static void lg_mutex_init(LgMutex *m) { pthread_mutex_init(m, NULL); }
static void lg_mutex_destroy(LgMutex *m) { pthread_mutex_destroy(m); }
static void lg_mutex_lock(LgMutex *m) { pthread_mutex_lock(m); }
static void lg_mutex_unlock(LgMutex *m) { pthread_mutex_unlock(m); }
static void lg_cond_init(LgCond *c) { pthread_cond_init(c, NULL); }
static void lg_cond_destroy(LgCond *c) { pthread_cond_destroy(c); }
static void lg_cond_wait(LgCond *c, LgMutex *m) { pthread_cond_wait(c, m); }
static void lg_cond_broadcast(LgCond *c) { pthread_cond_broadcast(c); }

static int lg_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

#endif

#endif

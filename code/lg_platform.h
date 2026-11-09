/* lg_platform.h - system headers and constants shared by all the modules.
 * It must be the first thing included: _POSIX_C_SOURCE has to be defined
 * before any system header. */
#ifndef LG_PLATFORM_H
#define LG_PLATFORM_H

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* condition variables */
#endif
#else
#define _POSIX_C_SOURCE 200112L /* mmap, fstat, posix_madvise, pthreads */
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
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define BLOCK_SIZE (1u << 20) /* 1 MiB read block when the file is not mapped */
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
#ifndef PAR_MIN_BYTES
#define PAR_MIN_BYTES ((size_t)16 << 20) /* smaller files are not worth the threads */
#endif
#ifndef MAX_AUTO_THREADS
#define MAX_AUTO_THREADS 16
#endif

#endif

#ifndef INJECT_H
#define INJECT_H
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if __x86_64__ || __ppc64__
    #define MX64
#else
    #define MX86
#endif

#define ERR(fmt, ...) printf("Error: " fmt, __VA_ARGS__)

typedef void* ptr_t;
typedef struct link_map link_map_t;

typedef union ptr_u
{
    ptr_t p;
    uintptr_t ui;
} ptr_u_t;

typedef struct string
{
    char* pc;
    size_t len;
    size_t maxlen;
} string_t;

typedef struct lib
{
    string_t filename;
    ptr_u_t base_addr;
} lib_t;

typedef struct lib_info
{
    lib_t* libs;
    int count;
} lib_info_t;

typedef uintptr_t (*thread_func_t)(ptr_u_t);

extern const char* __progname;
#endif

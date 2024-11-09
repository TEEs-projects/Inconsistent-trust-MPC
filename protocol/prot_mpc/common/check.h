#pragma once
#include <stdio.h>

#define check(expr) do { \
    if (!static_cast <bool> (expr)) { \
        fprintf(stderr, "%s:%u: Check %s failed.\n", __FILE__, __LINE__, #expr); \
        exit(1); \
    } \
} while (0);

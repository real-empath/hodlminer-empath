/* scratchpad_win.c
 * Minimal Windows stub: fall back to aligned heap allocation.
 * No huge pages, no mlock; optional pretouch to fault pages in.
 */
#ifdef _WIN32

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>   /* _aligned_malloc, _aligned_free */

#include "scratchpad.h"

#ifndef _aligned_malloc
/* Very old toolchains: degrade gracefully */
#  define _aligned_malloc(sz, al)  malloc(sz)
#  define _aligned_free(p)         free(p)
#endif

void* hodl_alloc_scratchpad(size_t bytes,
                            int /*want_huge*/,
                            int want_pretouch,
                            int /*want_mlock*/)
{
    /* 64B alignment is friendly to cache lines and AES loads */
    void* p = _aligned_malloc(bytes, 64);
    if (!p) return NULL;

    /* Optional: touch one byte per page to commit pages up front */
    if (want_pretouch) {
        volatile uint8_t* q = (volatile uint8_t*)p;
        const size_t pagesz = 4096;  /* Windows page size */
        for (size_t i = 0; i < bytes; i += pagesz)
            q[i] = 0;
    }
    return p;
}

void hodl_free_scratchpad(void* ptr, size_t /*bytes*/)
{
    if (ptr) _aligned_free(ptr);
}

#else
/* Built by mistake on non-Windows */
#  error "scratchpad_win.c should only be compiled on Windows (_WIN32)."
#endif

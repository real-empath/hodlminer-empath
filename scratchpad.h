#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* want_huge: try MAP_HUGETLB, fallback to MADV_HUGEPAGE
   want_pretouch: touch every page to fault it in
   want_mlock: mlock() the region (best effort; warns if it fails) */
void* hodl_alloc_scratchpad(size_t bytes, int want_huge, int want_pretouch, int want_mlock);
void  hodl_free_scratchpad(void* p, size_t bytes);

#ifdef __cplusplus
}
#endif

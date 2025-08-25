#include "scratchpad.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#if defined(__linux__)
  #define HODL_LINUX 1
#endif

/* If you have applog() already (from miner.h), include it and use it. */
#include "miner.h"  /* for applog(LOG_INFO/LOG_ERR, ...) */

static void pretouch_pages(char* p, size_t bytes) {
  const size_t page = (size_t) sysconf(_SC_PAGESIZE);
  for (size_t off = 0; off < bytes; off += page)
    p[off] = 0;     /* write to fault in & back it with RAM */
}

void* hodl_alloc_scratchpad(size_t bytes, int want_huge, int want_pretouch, int want_mlock)
{
  void* p = MAP_FAILED;
#if HODL_LINUX
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if (want_huge) {
    p = mmap(NULL, bytes, PROT_READ|PROT_WRITE, flags | MAP_HUGETLB, -1, 0);
    if (p == MAP_FAILED) {
      applog(LOG_INFO, "MAP_HUGETLB failed (errno=%d). "
                       "Try reserving hugepages: echo %zu > /proc/sys/vm/nr_hugepages",
                       errno, bytes / (2 * 1024 * 1024)); /* 2MiB pages typical */
    }
  }
  if (p == MAP_FAILED) {
    p = mmap(NULL, bytes, PROT_READ|PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) {
      applog(LOG_ERR, "mmap() failed for %zu bytes (errno=%d)", bytes, errno);
      return NULL;
    }
    /* Ask kernel for THP backing on the regular mapping */
#ifdef MADV_HUGEPAGE
    (void) madvise(p, bytes, MADV_HUGEPAGE);
#endif
  }

  if (want_mlock) {
    if (mlock(p, bytes) != 0) {
      applog(LOG_INFO, "mlock() failed (errno=%d). Increase ulimit -l or grant cap_ipc_lock.", errno);
      /* not fatal: keep going */
    }
  }

  if (want_pretouch)
    pretouch_pages((char*)p, bytes);

  return p;
#else
  /* Non-Linux fallback — just anonymous mmap */
  p = mmap(NULL, bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    applog(LOG_ERR, "mmap() failed for %zu bytes (errno=%d)", bytes, errno);
    return NULL;
  }
  if (want_mlock) (void) mlock(p, bytes);
  if (want_pretouch) pretouch_pages((char*)p, bytes);
  return p;
#endif
}

void hodl_free_scratchpad(void* p, size_t bytes)
{
  if (!p) return;
#if HODL_LINUX
  (void) munlock(p, bytes);
#endif
  (void) munmap(p, bytes);
}

CC = gcc
AM_CFLAGS = -Wall

if WANT_JANSSON
JANSSON_INCLUDES = -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES =
endif

EXTRA_DIST = example-cfg.json nomacro.pl
SUBDIRS    = compat

# Helpful so mmap/madvise flags are visible on Linux/glibc builds
AM_CPPFLAGS = -D_GNU_SOURCE

AM_CFLAGS  += $(PTHREAD_FLAGS) -march=native -O3 -fuse-linker-plugin -std=gnu11 $(JANSSON_INCLUDES)

bin_PROGRAMS   = hodlminer
dist_man_MANS  = hodlminer.1

# Pick the right scratchpad backend (WIN32 must be defined in configure.ac)
if WIN32
SCRATCHPAD_SRC = scratchpad_win.c
else
SCRATCHPAD_SRC = scratchpad_posix.c
endif

# Core sources (include headers you want packaged in 'make dist')
hodlminer_SOURCES = \
  elist.h miner.h compat.h scratchpad.h empath-aes-ng.h \
  sha2.c cpu-miner.c util.c hodl.c \
  empath-aes-ng.c \
  $(SCRATCHPAD_SRC)

# Add SHA512 SIMD units with arch guards (optional but safer cross-platform)
if ARCH_x86
hodlminer_SOURCES += sha512_sse2.c
endif
if ARCH_x86_64
hodlminer_SOURCES += sha512_avx2.c
endif

hodlminer_LDFLAGS  = $(PTHREAD_FLAGS)
hodlminer_LDADD    = @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ -lssl -lcrypto
hodlminer_CPPFLAGS = @LIBCURL_CPPFLAGS@

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

# Pick the right scratchpad backend (requires WIN32 automake conditional set in configure.ac)
if WIN32
SCRATCHPAD_SRC = scratchpad_win.c
else
SCRATCHPAD_SRC = scratchpad_posix.c
endif

hodlminer_SOURCES = \
  elist.h miner.h compat.h scratchpad.h \
  sha2.c cpu-miner.c util.c hodl.c \
  empath-aes-ng.c \
  sha512_sse2.c sha512_avx2.c \
  $(SCRATCHPAD_SRC)

hodlminer_LDFLAGS  = $(PTHREAD_FLAGS)
hodlminer_LDADD    = @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ -lssl -lcrypto
hodlminer_CPPFLAGS = @LIBCURL_CPPFLAGS@

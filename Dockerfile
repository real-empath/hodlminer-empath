# syntax=docker/dockerfile:1

############################
# Builder
############################
FROM debian:bookworm AS build

ARG DEBIAN_FRONTEND=noninteractive
# Parallel build jobs
ARG JOBS=8
# GENERIC=1 => avoid -march=native so the binary runs on more CPUs
ARG GENERIC=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config \
    libcurl4-openssl-dev libssl-dev \
    ca-certificates git make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Autotools bootstrap
RUN autoreconf -fi

# Configure & build
# We rely on bundled jansson (compat/jansson) by default; no libjansson-dev needed.
# If you want maximum portability, keep GENERIC=1 to avoid -march=native.
RUN if [ "$GENERIC" = "1" ]; then \
      CFLAGS="-O3 -pipe -fuse-linker-plugin -std=gnu11 -mtune=generic" ./configure; \
    else \
      ./configure; \
    fi \
 && make -j${JOBS} V=1 \
 && strip ./hodlminer

############################
# Runtime
############################
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 libssl3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/hodlminer /usr/local/bin/hodlminer

# Show help if no args provided
ENTRYPOINT ["hodlminer"]
CMD ["--help"]

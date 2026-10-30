# Image with the native libraries pazuzu loads, plus SBCL and Quicklisp.
# Build from the repository root:
#
#   docker build -t pazuzu-deps .
#   docker run --rm -v "$PWD":/src -w /src pazuzu-deps \
#     sbcl --noinform --disable-debugger \
#       --load /root/quicklisp/setup.lisp \
#       --eval '(asdf:load-asd (truename "pazuzu.asd"))' \
#       --eval '(ql:quickload :pazuzu)'
#
# The libraries are on the default loader path. curl in this image speaks HTTP/3.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config cmake \
        ca-certificates curl xz-utils python3 sbcl zlib1g-dev perl \
    && rm -rf /var/lib/apt/lists/*

COPY script/build-deps.sh /tmp/build-deps.sh
RUN chmod +x /tmp/build-deps.sh \
    && PREFIX=/usr/local /tmp/build-deps.sh \
    && rm -rf /tmp/pazuzu-deps-src /tmp/build-deps.sh

RUN curl -fsSL -o /tmp/quicklisp.lisp https://beta.quicklisp.org/quicklisp.lisp \
    && sbcl --noinform --disable-debugger --load /tmp/quicklisp.lisp \
         --eval '(quicklisp-quickstart:install)' \
         --quit \
    && rm -f /tmp/quicklisp.lisp

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PATH=/usr/local/bin:${PATH}
WORKDIR /src

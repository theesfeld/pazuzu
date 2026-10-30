# Production image. The binary and native libraries are installed under
# /usr/local. The process listens on 8080 unless /etc/pazuzu/config.lisp
# is replaced.
#
#   docker build -t pazuzu .
#   docker run --rm -p 8080:8080 pazuzu
FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config cmake \
        ca-certificates curl xz-utils python3 sbcl zlib1g-dev perl patchelf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN curl -fsSL -o /tmp/quicklisp.lisp https://beta.quicklisp.org/quicklisp.lisp \
    && sbcl --noinform --disable-debugger --load /tmp/quicklisp.lisp \
         --eval '(quicklisp-quickstart:install)' \
         --quit \
    && rm -f /tmp/quicklisp.lisp \
    && PREFIX=/opt/pazuzu ./script/build-deps.sh \
    && PAZUZU_DEPS=/opt/pazuzu ./script/build-binary.sh \
    && make install DESTDIR=/opt/root PREFIX=/usr/local PAZUZU_DEPS=/opt/pazuzu

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libffi8 zlib1g adduser \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --user-group --home-dir /var/lib/pazuzu \
         --shell /usr/sbin/nologin pazuzu \
    && install -d -o pazuzu -g pazuzu /var/lib/pazuzu/www /var/log/pazuzu
COPY --from=build /opt/root /
USER pazuzu
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pazuzu"]
CMD ["--config", "/etc/pazuzu/config.lisp"]

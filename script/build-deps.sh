#!/usr/bin/env bash
# Build and install the native libraries pazuzu loads, at the versions
# src/http2.lisp and src/http3.lisp require.
#
#   nghttp2 1.70.0          version_num #x014600
#   ngtcp2  1.25.0          version_num #x011900, OpenSSL crypto backend
#   nghttp3 1.18.0          version_num #x011200
#   brotli  1.1.1           libbrotlienc, libbrotlidec
#   zstd    1.5.7           libzstd
#   OpenSSL 3.5.9           libngtcp2_crypto_ossl needs the QUIC callbacks
#                           in OpenSSL >= 3.5 (SSL_set_quic_tls_cbs)
#
# curl 8.23.0 is installed into the same prefix with HTTP/3, brotli, and
# zstd so the test suite's `curl --http3-only` is the curl on PATH.
#
# Usage:
#   sudo PREFIX=/usr/local ./script/build-deps.sh
#   PREFIX=/opt/pazuzu ./script/build-deps.sh
#
# A matching stamp under $PREFIX skips the build. Delete the stamp to rebuild.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
OPENSSL_VERSION=3.5.9
NGHTTP2_VERSION=1.70.0
NGTCP2_VERSION=1.25.0
NGHTTP3_VERSION=1.18.0
BROTLI_VERSION=1.1.1
ZSTD_VERSION=1.5.7
CURL_VERSION=8.23.0

JOBS="${JOBS:-$(nproc)}"
SRC="${SRC:-${TMPDIR:-/tmp}/pazuzu-deps-src}"
STAMP="$PREFIX/share/pazuzu/deps-stamp"
WANT="openssl ${OPENSSL_VERSION}
nghttp2 ${NGHTTP2_VERSION}
ngtcp2 ${NGTCP2_VERSION}
nghttp3 ${NGHTTP3_VERSION}
brotli ${BROTLI_VERSION}
zstd ${ZSTD_VERSION}
curl ${CURL_VERSION}"

if [[ -f "$STAMP" && "$(cat "$STAMP")" == "$WANT" \
      && -e "$PREFIX/lib/libnghttp2.so" \
      && -e "$PREFIX/lib/libngtcp2.so" \
      && -e "$PREFIX/lib/libngtcp2_crypto_ossl.so" \
      && -e "$PREFIX/lib/libnghttp3.so" \
      && -e "$PREFIX/lib/libbrotlienc.so" \
      && -e "$PREFIX/lib/libbrotlidec.so" \
      && -e "$PREFIX/lib/libzstd.so" \
      && -x "$PREFIX/bin/curl" \
      && -f "$PREFIX/ssl/openssl.cnf" ]]; then
  echo "pazuzu deps already installed in $PREFIX"
  exit 0
fi

if [[ ! -w "$(dirname "$PREFIX")" && ! -w "$PREFIX" ]]; then
  echo "cannot write $PREFIX; re-run with a writable PREFIX or as root" >&2
  exit 1
fi

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

mkdir -p "$SRC" "$PREFIX"
cd "$SRC"

fetch() {
  local url="$1"
  local dest="$2"
  echo "==> fetch $url"
  curl -fL --retry 3 --retry-delay 2 -o "$dest" "$url"
}

build_openssl() {
  local ver="$OPENSSL_VERSION"
  if [[ ! -d "openssl-$ver" ]]; then
    fetch "https://github.com/openssl/openssl/releases/download/openssl-${ver}/openssl-${ver}.tar.gz" \
      "openssl-$ver.tar.gz"
    tar -xzf "openssl-$ver.tar.gz"
  fi
  cd "openssl-$ver"
  ./Configure "linux-$(uname -m)" shared \
    --prefix="$PREFIX" --libdir=lib --openssldir="$PREFIX/ssl" \
    -Wl,-rpath,'$ORIGIN'
  make -j"$JOBS"
  make install_sw
  # install_sw omits openssl.cnf. The openssl CLI, including the one the
  # test suite uses to mint certificates, reads it from this prefix.
  make install_ssldirs
  cd "$SRC"
  # $ORIGIN keeps a copied lib directory working after make install moves it.
  # CFFI dlopen of libngtcp2_crypto_ossl then finds libssl beside it.
  export LDFLAGS="-Wl,-rpath,\$ORIGIN ${LDFLAGS:-}"
  export CPPFLAGS="-I${PREFIX}/include ${CPPFLAGS:-}"
}

build_autotools() {
  local name="$1"
  local ver="$2"
  local url="$3"
  local extra="${4:-}"
  if [[ ! -d "$name-$ver" ]]; then
    fetch "$url" "$name-$ver.tar.xz"
    tar -xJf "$name-$ver.tar.xz"
  fi
  cd "$name-$ver"
  # shellcheck disable=SC2086
  ./configure --prefix="$PREFIX" --enable-lib-only $extra
  make -j"$JOBS"
  make install
  cd "$SRC"
}

build_brotli() {
  local ver="$BROTLI_VERSION"
  if [[ ! -d "brotli-$ver" ]]; then
    fetch "https://github.com/google/brotli/archive/refs/tags/v${ver}.tar.gz" \
      "brotli-$ver.tar.gz"
    tar -xzf "brotli-$ver.tar.gz"
  fi
  cmake -S "brotli-$ver" -B "brotli-$ver/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=ON
  cmake --build "brotli-$ver/build" -j"$JOBS"
  cmake --install "brotli-$ver/build"
}

build_zstd() {
  local ver="$ZSTD_VERSION"
  if [[ ! -d "zstd-$ver" ]]; then
    fetch "https://github.com/facebook/zstd/releases/download/v${ver}/zstd-${ver}.tar.gz" \
      "zstd-$ver.tar.gz"
    tar -xzf "zstd-$ver.tar.gz"
  fi
  make -C "zstd-$ver" -j"$JOBS" PREFIX="$PREFIX"
  make -C "zstd-$ver" install PREFIX="$PREFIX"
}

build_curl() {
  local ver="$CURL_VERSION"
  if [[ ! -d "curl-$ver" ]]; then
    fetch "https://github.com/curl/curl/releases/download/curl-${ver//./_}/curl-${ver}.tar.xz" \
      "curl-$ver.tar.xz"
    tar -xJf "curl-$ver.tar.xz"
  fi
  cd "curl-$ver"
  ./configure --prefix="$PREFIX" \
    --with-openssl="$PREFIX" \
    --with-nghttp2="$PREFIX" \
    --with-nghttp3="$PREFIX" \
    --with-ngtcp2="$PREFIX" \
    --with-brotli="$PREFIX" \
    --with-zstd="$PREFIX" \
    --with-zlib \
    --without-libpsl \
    --disable-ldap \
    --disable-ldaps
  make -j"$JOBS"
  make install
  cd "$SRC"
}

echo "==> OpenSSL $OPENSSL_VERSION"
build_openssl
echo "==> nghttp2 $NGHTTP2_VERSION"
build_autotools nghttp2 "$NGHTTP2_VERSION" \
  "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.xz"
echo "==> nghttp3 $NGHTTP3_VERSION"
build_autotools nghttp3 "$NGHTTP3_VERSION" \
  "https://github.com/ngtcp2/nghttp3/releases/download/v${NGHTTP3_VERSION}/nghttp3-${NGHTTP3_VERSION}.tar.xz"
echo "==> ngtcp2 $NGTCP2_VERSION (OpenSSL crypto backend)"
build_autotools ngtcp2 "$NGTCP2_VERSION" \
  "https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2_VERSION}/ngtcp2-${NGTCP2_VERSION}.tar.xz" \
  "--with-openssl --without-gnutls --without-boringssl --without-picotls --without-wolfssl --disable-cryptotest"
echo "==> brotli $BROTLI_VERSION"
build_brotli
echo "==> zstd $ZSTD_VERSION"
build_zstd
echo "==> curl $CURL_VERSION"
build_curl

mkdir -p "$(dirname "$STAMP")"
printf '%s\n' "$WANT" > "$STAMP"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "$PREFIX/lib" > /etc/ld.so.conf.d/pazuzu.conf
  ldconfig
else
  echo "Not root: add $PREFIX/lib to the loader path before starting SBCL:"
  echo "  export LD_LIBRARY_PATH=$PREFIX/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
  echo "  export PATH=$PREFIX/bin:\$PATH"
fi

echo "installed into $PREFIX"
pkg-config --modversion libnghttp2
pkg-config --modversion libngtcp2
pkg-config --modversion libnghttp3
test -e "$PREFIX/lib/libngtcp2_crypto_ossl.so"
"$PREFIX/bin/curl" --version | head -n 2

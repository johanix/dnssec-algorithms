#!/bin/sh
# Build a minimal, static, no-OpenSSL liboqs and install a matching
# liboqs-go.pc pointing at it. Intended for NetBSD and Linux build
# hosts that produce standalone tdns binaries. On macOS, prefer the
# dynamic pre-built /opt/local liboqs and the macos-dev .pc template.
#
# Usage:
#   sh build-liboqs-static.sh [prefix]
#
# Default prefix: /usr/local/liboqs-static
# Resulting .pc:  <prefix>/lib/pkgconfig/liboqs-go.pc
#
# After the script finishes, set:
#   export PKG_CONFIG_PATH=<prefix>/lib/pkgconfig:$PKG_CONFIG_PATH
# in the build environment, then `go build` your tdns binaries as
# usual.

set -e

PREFIX=${1:-/usr/local/liboqs-static}
VERSION=0.15.0
BUILDDIR=$(mktemp -d -t liboqs-static-build.XXXXXX)

echo "==> Building liboqs ${VERSION} (static, no-OpenSSL, minimal-build)"
echo "    prefix:    ${PREFIX}"
echo "    workspace: ${BUILDDIR}"

cd "${BUILDDIR}"
git clone --depth 1 --branch "${VERSION}" \
   https://github.com/open-quantum-safe/liboqs.git src
cd src
mkdir build && cd build

cmake \
   -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
   -DCMAKE_BUILD_TYPE=Release \
   -DBUILD_SHARED_LIBS=OFF \
   -DOQS_USE_OPENSSL=OFF \
   -DOQS_BUILD_ONLY_LIB=ON \
   -DOQS_MINIMAL_BUILD="OQS_ENABLE_SIG_falcon_512;OQS_ENABLE_SIG_mayo_1;OQS_ENABLE_SIG_snova_SNOVA_24_5_4" \
   ..

make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu || echo 1)"
make install

# Drop a liboqs-go.pc that emits explicit static-link flags. The
# linker pulls in the .a directly via full path so we don't depend on
# -Wl,-Bstatic semantics that differ across GNU ld / lld.
mkdir -p "${PREFIX}/lib/pkgconfig"
cat > "${PREFIX}/lib/pkgconfig/liboqs-go.pc" <<EOF
LIBOQS_INCLUDE_DIR=${PREFIX}/include
LIBOQS_LIB_DIR=${PREFIX}/lib

Name: liboqs-go
Description: Go bindings for liboqs (static, no-OpenSSL build for production)
Version: ${VERSION}
Cflags: -I\${LIBOQS_INCLUDE_DIR}
Libs: \${LIBOQS_LIB_DIR}/liboqs.a
EOF

echo
echo "==> Done."
echo "    Static archive: ${PREFIX}/lib/liboqs.a"
echo "    pkg-config .pc: ${PREFIX}/lib/pkgconfig/liboqs-go.pc"
echo
echo "Add this to your shell / build environment:"
echo "    export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH"
echo
echo "Then go-build your tdns binaries; liboqs will be statically"
echo "linked in, no runtime liboqs or libcrypto dependency."

rm -rf "${BUILDDIR}"

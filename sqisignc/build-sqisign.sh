#!/bin/sh
# Build the-sqisign reference C library (lvl1 only) and install
# headers + static archives + a matching sqisign.pc under a chosen
# prefix. Upstream the-sqisign ships no `install` rules of its own,
# so this script picks the artifacts out of the CMake build tree by
# hand.
#
# Usage:
#   sh build-sqisign.sh [prefix]
#
# Default prefix: /usr/local/sqisign-lvl1
# Resulting .pc:  <prefix>/lib/pkgconfig/sqisign.pc
#
# After the script finishes, set:
#   export PKG_CONFIG_PATH=<prefix>/lib/pkgconfig:$PKG_CONFIG_PATH
# in the build environment, then `go build` your dnssec-algorithms
# consumer as usual.
#
# Build host requirements:
#   - cmake >= 3.13
#   - C11 compiler (gcc or clang)
#   - GMP development headers + library (libgmp / gmp-dev / etc.)
#   - git, make, sh
#
# On macOS MacPorts:        `port install cmake gmp`
# On NetBSD pkgsrc:         `pkgin install cmake gmp`
# On Debian/Ubuntu:         `apt install cmake libgmp-dev`

set -e

PREFIX=${1:-/usr/local/sqisign-lvl1}
# Pin to a known-good upstream commit/tag rather than tracking main.
# Update this together with the byte-size constants in sqisignc.go if
# upstream bumps any of CRYPTO_PUBLICKEYBYTES / CRYPTO_SECRETKEYBYTES
# / CRYPTO_BYTES.
SQISIGN_REF=${SQISIGN_REF:-main}
BUILDDIR=$(mktemp -d -t sqisign-build.XXXXXX)

echo "==> Building the-sqisign (lvl1) reference impl"
echo "    upstream:  https://github.com/SQISign/the-sqisign"
echo "    ref:       ${SQISIGN_REF}"
echo "    prefix:    ${PREFIX}"
echo "    workspace: ${BUILDDIR}"

cd "${BUILDDIR}"
git clone https://github.com/SQISign/the-sqisign.git src
cd src
git checkout "${SQISIGN_REF}"

mkdir build && cd build
cmake \
   -DCMAKE_BUILD_TYPE=Release \
   -DSQISIGN_BUILD_TYPE=ref \
   -DENABLE_STRICT=OFF \
   -DENABLE_TESTS=OFF \
   -DENABLE_SIGN=ON \
   -DGMP_LIBRARY=SYSTEM \
   ..

make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu || echo 1)" \
   sqisign_lvl1_nistapi

# Upstream has no install() rules. Pick out everything we need by hand.
#
# Public-API headers we need to compile against:
#   - include/sig.h, sqisign_namespace.h, mem.h, rng.h  (from src tree)
#   - src/nistapi/lvl1/api.h  (defines the CRYPTO_* constants we use)
#
# Static archives to link: the recursive dep chain rooted at
# libsqisign_lvl1_nistapi.a. Easier to glob every .a from the build
# tree than to enumerate by name — the upstream library set evolves
# between releases.

INSTALL_INC="${PREFIX}/include"
INSTALL_LIB="${PREFIX}/lib"
INSTALL_PC="${INSTALL_LIB}/pkgconfig"

mkdir -p "${INSTALL_INC}" "${INSTALL_LIB}" "${INSTALL_PC}"

# Public headers. api.h goes alongside sig.h so the Go CGO directive
# `#include "api.h"` works with a single -I${INSTALL_INC}.
cp ../include/sig.h              "${INSTALL_INC}/"
cp ../include/sqisign_namespace.h "${INSTALL_INC}/"
cp ../include/mem.h              "${INSTALL_INC}/"
cp ../include/rng.h              "${INSTALL_INC}/"
cp ../src/nistapi/lvl1/api.h     "${INSTALL_INC}/"

# Static archives. Enumerate the lvl1 lib set explicitly rather than
# glob-copy every .a — upstream's CMake probes (try_compile, etc.)
# can leave stray libraries like libfoo.a in the build tree, and a
# glob would sweep them into the install set.
#
# Order matters for static-link resolution: a consumer must appear
# before its dependency on the linker command line. The NIST-API
# archive is the entry point our Go wrapper calls into, so it goes
# first; libsqisign_lvl1 wraps the rest; the per-component archives
# follow; libgmp / libm close out the line.
LVL1_LIBS="
libsqisign_lvl1_nistapi.a
libsqisign_lvl1.a
libsqisign_signature_lvl1.a
libsqisign_verification_lvl1.a
libsqisign_id2iso_lvl1.a
libsqisign_quaternion_generic.a
libsqisign_hd_lvl1.a
libsqisign_ec_lvl1.a
libsqisign_precomp_lvl1.a
libsqisign_gf_lvl1.a
libsqisign_mp_generic.a
libsqisign_common_sys.a
"

LIBS_LINE=""
for libname in ${LVL1_LIBS}; do
   src=$(find . -name "${libname}" -type f | head -1)
   if [ -z "${src}" ]; then
      echo "==> ERROR: expected lib ${libname} not produced by the build" >&2
      exit 1
   fi
   cp "${src}" "${INSTALL_LIB}/"
   LIBS_LINE="${LIBS_LINE} \${SQISIGN_LIB_DIR}/${libname}"
done
LIBS_LINE="${LIBS_LINE} -lgmp -lm"

cat > "${INSTALL_PC}/sqisign.pc" <<EOF
SQISIGN_INCLUDE_DIR=${INSTALL_INC}
SQISIGN_LIB_DIR=${INSTALL_LIB}

Name: sqisign
Description: SQIsign-I reference implementation (the-sqisign), static build
Version: 0
Cflags: -I\${SQISIGN_INCLUDE_DIR} -DENABLE_SIGN=1 -DSQISIGN_VARIANT=lvl1 -DSQISIGN_BUILD_TYPE_REF
Libs: ${LIBS_LINE}
EOF

echo
echo "==> Done."
echo "    Headers:        ${INSTALL_INC}"
echo "    Static archives: ${INSTALL_LIB}/lib*.a"
echo "    pkg-config .pc: ${INSTALL_PC}/sqisign.pc"
echo
echo "Add this to your shell / build environment:"
echo "    export PKG_CONFIG_PATH=${INSTALL_PC}:\$PKG_CONFIG_PATH"
echo
echo "Then go-build your dnssec-algorithms consumer."

rm -rf "${BUILDDIR}"

#!/bin/sh
# Build the QR-UOV round2 reference C implementation for a single
# pinned parameter set and install headers + a static archive + a
# matching qruov.pc under a chosen prefix.
#
# Unlike the-sqisign (which ships a CMake build producing static
# archives we cherry-pick), QR-UOV's reference is a flat set of C
# source files whose parameter set is selected entirely by -D macros
# at compile time. Two of its headers (qruov_config.h, api.h) are not
# checked in at all — they are emitted by running small generator
# programs (qruov_config_h_gen.c, api_h_gen.c) with the parameter
# macros applied. This script reproduces that generation, then bundles
# the result into one static archive plus a pkg-config file so the Go
# CGO wrapper can `#include "api.h"` and link against a single -lqruov.
#
# Only ONE parameter set lives in a given archive (the CRYPTO_* sizes
# and the internal field arithmetic are all compile-time constants).
# This script pins QR-UOV-I (q=31, L=3, v=165, m=60), chosen for the
# smallest signature (157 bytes) at NIST security level 1. To wire up
# a different set, change QRUOV_PARAMS below and bump the byte-size
# constants in qruovc.go to whatever the generated api.h reports.
#
# Usage:
#   sh build-qruov.sh [prefix]
#
# Default prefix: /usr/local/qruov-i
# Resulting .pc:  <prefix>/lib/pkgconfig/qruov.pc
#
# After the script finishes, set:
#   export PKG_CONFIG_PATH=<prefix>/lib/pkgconfig:$PKG_CONFIG_PATH
# in the build environment, then `go build` your dnssec-algorithms
# consumer as usual.
#
# Build host requirements:
#   - C11 compiler (gcc or clang)
#   - OpenSSL development headers + library (libcrypto: the reference
#     MGF/PRG and the NIST KAT DRBG depend on it)
#   - git, make, ar, sh
#
# On macOS MacPorts:   `port install openssl`
# On NetBSD pkgsrc:    `pkgin install openssl`
# On Debian/Ubuntu:    `apt install libssl-dev`
#
# NOTE: the round2 reference Makefile builds with -fopenmp and
# -march=native. We deliberately drop both here: -march=native makes
# the archive non-portable across build/run hosts (the tdns project
# builds on one machine and runs on others), and the OpenMP
# parallelism in keygen is not needed for correctness. Add -fopenmp
# back if you want the faster multi-threaded keygen and your toolchain
# ships libgomp/libomp.

set -e

PREFIX=${1:-/usr/local/qruov-i}
# Resolve PREFIX to an absolute path before we cd into the build tree.
# A relative prefix (e.g. ./local-install) would otherwise land inside
# the temporary clone and vanish when it is cleaned up.
case "$PREFIX" in
   /*) : ;;                       # already absolute
   *)  mkdir -p "$PREFIX"; PREFIX=$(cd "$PREFIX" && pwd) ;;
esac
# Pin to a known-good upstream commit rather than tracking main.
# Update this together with the byte-size constants in qruovc.go if
# upstream regenerates api.h with different CRYPTO_* values.
QRUOV_REF=${QRUOV_REF:-main}

# The pinned parameter set. These eight -D values come verbatim from
# the round2 src/qruov_config.src line for qruov1q31L3v165m60. The
# ref platform is the portable, non-vectorized C implementation.
QRUOV_PARAMS="-DQRUOV_security_strength_category=1 -DQRUOV_q=31 -DQRUOV_L=3 -DQRUOV_v=165 -DQRUOV_m=60 -DQRUOV_fc=1 -DQRUOV_fe=1 -DQRUOV_fc0=1"
QRUOV_PLATFORM=ref

BUILDDIR=$(mktemp -d -t qruov-build.XXXXXX)

echo "==> Building QR-UOV round2 reference impl (single parameter set)"
echo "    upstream:  https://github.com/qruov/round2"
echo "    ref:       ${QRUOV_REF}"
echo "    params:    q=31 L=3 v=165 m=60 (QR-UOV-I, 157-byte signatures)"
echo "    platform:  ${QRUOV_PLATFORM}"
echo "    prefix:    ${PREFIX}"
echo "    workspace: ${BUILDDIR}"

cd "${BUILDDIR}"
git clone https://github.com/qruov/round2.git src
cd src
git checkout "${QRUOV_REF}"
cd "src/${QRUOV_PLATFORM}"

# Resolve OpenSSL include/lib flags via pkg-config when available,
# falling back to a bare -lcrypto otherwise.
if pkg-config --exists libcrypto 2>/dev/null; then
   SSL_CFLAGS=$(pkg-config --cflags libcrypto)
   SSL_LIBS=$(pkg-config --libs libcrypto)
else
   SSL_CFLAGS=""
   SSL_LIBS="-lcrypto"
fi

CC=${CC:-cc}
CFLAGS="-O3 -fomit-frame-pointer -fwrapv -fPIC -Wno-deprecated-declarations -Wno-unused-result ${SSL_CFLAGS}"

# The ref platform's matrix.c carries a stray `#include <x86intrin.h>`
# but calls no x86 intrinsics (the vectorized code lives in the avx2 /
# avx512 platforms). That include fails to compile on non-x86 hosts
# (e.g. Apple Silicon, arm64 NetBSD/Linux), so strip it. Harmless on
# x86. Done in-tree before compilation; portable across GNU/BSD sed via
# a tmpfile rewrite rather than `sed -i` (whose flag syntax differs).
if grep -q '#include <x86intrin.h>' matrix.c; then
   grep -v '#include <x86intrin.h>' matrix.c > matrix.c.tmp
   mv matrix.c.tmp matrix.c
   echo "==> Stripped stray <x86intrin.h> include from matrix.c (ref is non-vectorized)"
fi

# Step 1: generate qruov_config.h (parameter macros -> derived config)
# and api.h (the CRYPTO_* size constants + crypto_sign prototypes).
# Both generators are compile-and-run programs, exactly as the
# upstream Makefile drives them.
echo "==> Generating qruov_config.h"
${CC} ${QRUOV_PARAMS} -DQRUOV_PLATFORM=${QRUOV_PLATFORM} -DQRUOV_CONFIG_H_GEN ${CFLAGS} qruov_config_h_gen.c ${SSL_LIBS} -o gen_config
./gen_config > qruov_config.h
rm -f gen_config

echo "==> Generating api.h"
${CC} -DAPI_H_GEN ${CFLAGS} api_h_gen.c ${SSL_LIBS} -o gen_api
./gen_api > api.h
rm -f gen_api

echo "==> Reported sizes:"
grep -E 'CRYPTO_(SECRETKEY|PUBLICKEY)BYTES|CRYPTO_BYTES|CRYPTO_ALGNAME' api.h | sed 's/^/    /'

# Step 2: compile the library translation units (everything the
# crypto_sign API depends on) into objects, then archive. We exclude
# PQCgenKAT_sign.c (the KAT harness with its own main()).
echo "==> Compiling library objects"
LIB_SRCS="Fql.c qruov.c sign.c matrix.c mgf.c rng.c"
OBJS=""
for src in ${LIB_SRCS}; do
   obj="${src%.c}.o"
   # No -DQRUOV_PLATFORM here: the generated qruov_config.h already
   # defines it (as "refa"), and passing it again on the command line
   # triggers a -Wmacro-redefined warning.
   ${CC} ${QRUOV_PARAMS} ${CFLAGS} -c "${src}" -o "${obj}"
   OBJS="${OBJS} ${obj}"
done

echo "==> Archiving libqruov.a"
ar rcs libqruov.a ${OBJS}

# Step 3: install headers + archive + .pc.
INSTALL_INC="${PREFIX}/include"
INSTALL_LIB="${PREFIX}/lib"
INSTALL_PC="${INSTALL_LIB}/pkgconfig"
mkdir -p "${INSTALL_INC}" "${INSTALL_LIB}" "${INSTALL_PC}"

# Headers the Go CGO directive (and api.h itself) need to compile.
# This is the full transitive include set of qruov.h: the public
# api.h, the generated config, and every "..."-included header in the
# ref tree (qruov_tau.h and post_sample.h are pulled in by qruov.h /
# qruov.c).
cp api.h qruov.h qruov_config.h qruov_misc.h qruov_tau.h post_sample.h \
   Fql.h matrix.h mgf.h rng.h refcount.h "${INSTALL_INC}/"
cp libqruov.a "${INSTALL_LIB}/"

cat > "${INSTALL_PC}/qruov.pc" <<EOF
QRUOV_INCLUDE_DIR=${INSTALL_INC}
QRUOV_LIB_DIR=${INSTALL_LIB}

Name: qruov
Description: QR-UOV-I (q=31 L=3 v165 m60) round2 reference implementation, static build
Version: 0
Cflags: -I\${QRUOV_INCLUDE_DIR} ${SSL_CFLAGS}
Libs: \${QRUOV_LIB_DIR}/libqruov.a ${SSL_LIBS} -lm
EOF

echo
echo "==> Done."
echo "    Headers:         ${INSTALL_INC}"
echo "    Static archive:  ${INSTALL_LIB}/libqruov.a"
echo "    pkg-config .pc:  ${INSTALL_PC}/qruov.pc"
echo
echo "Add this to your shell / build environment:"
echo "    export PKG_CONFIG_PATH=${INSTALL_PC}:\$PKG_CONFIG_PATH"
echo
echo "Then go-build your dnssec-algorithms consumer."

rm -rf "${BUILDDIR}"

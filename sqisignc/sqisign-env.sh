#!/bin/sh
# sqisign-env.sh — set up CGO build environment for the sqisignc
# package (and consumers like the sqisign1 algorithm subpackage).
#
# Unlike liboqs, the-sqisign is not packaged in MacPorts, pkgsrc, or
# any Linux distro yet, so there's no system-default install location
# to auto-detect. This script looks at a handful of plausible
# self-built prefixes plus whatever the caller hands us via
# SQISIGN_PREFIX, picks the first one that contains a valid
# sqisign.pc, and exports PKG_CONFIG_PATH (and CGO_LDFLAGS where the
# Go-cgo pkg-config integration needs help).
#
# To produce a usable install, run build-sqisign.sh first (see
# README.md). Default install prefix from build-sqisign.sh is
# /usr/local/sqisign-lvl1, which is the first thing we probe.
#
# Usage:
#   . sqisignc/sqisign-env.sh                # source: sets vars in current shell
#   eval "$(sqisignc/sqisign-env.sh)"        # equivalent
#   sqisignc/sqisign-env.sh                  # bare: just prints what to export
#
# Override detection:
#   SQISIGN_PREFIX=/path/to/prefix           # forces a specific install root
#
# Idempotent — safe to source multiple times.

# Locate this script's directory (works when sourced too).
__sqi_env_self=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)
if [ -z "$__sqi_env_self" ]; then
   __sqi_env_self=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
fi

__sqi_env_uname=$(uname -s 2>/dev/null || echo unknown)
case "$__sqi_env_uname" in
   NetBSD)
      __sqi_env_search='/usr/local/sqisign-lvl1
/usr/pkg
/usr/local'
      __sqi_env_cgo_ldflags=""
      __sqi_env_os_note="NetBSD (self-built static archive; system libgmp)"
      ;;
   Darwin)
      __sqi_env_search='/usr/local/sqisign-lvl1
/opt/local/sqisign-lvl1
/opt/local
/opt/homebrew/sqisign-lvl1
/opt/homebrew
/usr/local'
      __sqi_env_cgo_ldflags=""
      __sqi_env_os_note="macOS dev (self-built static archive; libgmp via MacPorts/Homebrew)"
      ;;
   Linux)
      __sqi_env_search='/usr/local/sqisign-lvl1
/usr/local
/opt/sqisign-lvl1'
      __sqi_env_cgo_ldflags=""
      __sqi_env_os_note="Linux (self-built static archive; system libgmp)"
      ;;
   *)
      echo "# sqisign-env.sh: unsupported OS '$__sqi_env_uname'" >&2
      return 1 2>/dev/null || exit 1
      ;;
esac

# Probe a prefix: return 0 if it has lib/pkgconfig/sqisign.pc.
__sqi_env_probe() {
   __p=$1
   [ -f "$__p/lib/pkgconfig/sqisign.pc" ] || return 1
   return 0
}

if [ -n "$SQISIGN_PREFIX" ]; then
   if __sqi_env_probe "$SQISIGN_PREFIX"; then
      __sqi_env_prefix="$SQISIGN_PREFIX"
      __sqi_env_chosen="$SQISIGN_PREFIX (SQISIGN_PREFIX)"
   else
      echo "# sqisign-env.sh: SQISIGN_PREFIX=$SQISIGN_PREFIX has no lib/pkgconfig/sqisign.pc" >&2
      return 1 2>/dev/null || exit 1
   fi
else
   while IFS= read -r __p; do
      [ -z "$__p" ] && continue
      if __sqi_env_probe "$__p"; then
         __sqi_env_prefix="$__p"
         __sqi_env_chosen="$__p (auto-detected)"
         break
      fi
   done <<EOF
$__sqi_env_search
EOF
fi

if [ -z "$__sqi_env_prefix" ]; then
   echo "# sqisign-env.sh: no sqisign.pc found under any of:" >&2
   echo "$__sqi_env_search" | sed 's/^/#   /' >&2
   echo "# Build and install the-sqisign first:" >&2
   echo "#   sh $__sqi_env_self/build-sqisign.sh [prefix]" >&2
   echo "# Platform note: $__sqi_env_os_note" >&2
   return 1 2>/dev/null || exit 1
fi

__sqi_env_pkg_dir="$__sqi_env_prefix/lib/pkgconfig"
echo "# sqisign-env.sh: detected sqisign install at $__sqi_env_chosen" >&2

if [ -n "$PKG_CONFIG_PATH" ]; then
   __sqi_env_pkg_path="${__sqi_env_pkg_dir}:${PKG_CONFIG_PATH}"
else
   __sqi_env_pkg_path="${__sqi_env_pkg_dir}"
fi

PKG_CONFIG_PATH="$__sqi_env_pkg_path"
export PKG_CONFIG_PATH
echo "export PKG_CONFIG_PATH=\"$__sqi_env_pkg_path\""

if [ -n "$__sqi_env_cgo_ldflags" ]; then
   CGO_LDFLAGS="$__sqi_env_cgo_ldflags"
   export CGO_LDFLAGS
   echo "export CGO_LDFLAGS=\"$__sqi_env_cgo_ldflags\""
fi

unset __sqi_env_self __sqi_env_uname __sqi_env_search \
   __sqi_env_cgo_ldflags __sqi_env_os_note __sqi_env_prefix \
   __sqi_env_chosen __sqi_env_pkg_dir __sqi_env_pkg_path __p
unset -f __sqi_env_probe 2>/dev/null

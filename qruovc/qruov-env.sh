#!/bin/sh
# qruov-env.sh — set up CGO build environment for the qruovc package
# (and consumers like the qruov1 algorithm subpackage).
#
# QR-UOV's round2 reference is not packaged anywhere, so there is no
# system-default install location to auto-detect. This script looks at
# a handful of plausible self-built prefixes plus whatever the caller
# hands us via QRUOV_PREFIX, picks the first one that contains a valid
# qruov.pc, and exports PKG_CONFIG_PATH.
#
# To produce a usable install, run build-qruov.sh first (see
# README.md). Default install prefix from build-qruov.sh is
# /usr/local/qruov-i, which is the first system path we probe.
#
# Usage:
#   . qruovc/qruov-env.sh                 # source: sets vars in current shell
#   eval "$(qruovc/qruov-env.sh)"         # equivalent
#   qruovc/qruov-env.sh                   # bare: just prints what to export
#
# Override detection:
#   QRUOV_PREFIX=/path/to/prefix          # forces a specific install root
#
# Idempotent — safe to source multiple times.

# Locate this script's directory (works when sourced too).
__qruov_env_self=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)
if [ -z "$__qruov_env_self" ]; then
   __qruov_env_self=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
fi

__qruov_env_uname=$(uname -s 2>/dev/null || echo unknown)
# The script's own directory is the natural place developers run
# build-qruov.sh into (./local-install/), so probe that first.
__qruov_env_local="$__qruov_env_self/local-install"
case "$__qruov_env_uname" in
   NetBSD)
      __qruov_env_search="$__qruov_env_local
/usr/local/qruov-i
/usr/pkg
/usr/local"
      __qruov_env_os_note="NetBSD (self-built static archive; system libcrypto)"
      ;;
   Darwin)
      __qruov_env_search="$__qruov_env_local
/usr/local/qruov-i
/opt/local/qruov-i
/opt/local
/opt/homebrew/qruov-i
/opt/homebrew
/usr/local"
      __qruov_env_os_note="macOS dev (self-built static archive; libcrypto via MacPorts/Homebrew)"
      ;;
   Linux)
      __qruov_env_search="$__qruov_env_local
/usr/local/qruov-i
/usr/local
/opt/qruov-i"
      __qruov_env_os_note="Linux (self-built static archive; system libcrypto)"
      ;;
   *)
      echo "# qruov-env.sh: unsupported OS '$__qruov_env_uname'" >&2
      return 1 2>/dev/null || exit 1
      ;;
esac

# Probe a prefix: return 0 if it has lib/pkgconfig/qruov.pc.
__qruov_env_probe() {
   __p=$1
   [ -f "$__p/lib/pkgconfig/qruov.pc" ] || return 1
   return 0
}

if [ -n "$QRUOV_PREFIX" ]; then
   if __qruov_env_probe "$QRUOV_PREFIX"; then
      __qruov_env_prefix="$QRUOV_PREFIX"
      __qruov_env_chosen="$QRUOV_PREFIX (QRUOV_PREFIX)"
   else
      echo "# qruov-env.sh: QRUOV_PREFIX=$QRUOV_PREFIX has no lib/pkgconfig/qruov.pc" >&2
      return 1 2>/dev/null || exit 1
   fi
else
   while IFS= read -r __p; do
      [ -z "$__p" ] && continue
      if __qruov_env_probe "$__p"; then
         __qruov_env_prefix="$__p"
         __qruov_env_chosen="$__p (auto-detected)"
         break
      fi
   done <<EOF
$__qruov_env_search
EOF
fi

if [ -z "$__qruov_env_prefix" ]; then
   echo "# qruov-env.sh: no qruov.pc found under any of:" >&2
   echo "$__qruov_env_search" | sed 's/^/#   /' >&2
   echo "# Build and install the round2 reference first:" >&2
   echo "#   sh $__qruov_env_self/build-qruov.sh [prefix]" >&2
   echo "# Platform note: $__qruov_env_os_note" >&2
   return 1 2>/dev/null || exit 1
fi

__qruov_env_pkg_dir="$__qruov_env_prefix/lib/pkgconfig"
echo "# qruov-env.sh: detected qruov install at $__qruov_env_chosen" >&2

if [ -n "$PKG_CONFIG_PATH" ]; then
   __qruov_env_pkg_path="${__qruov_env_pkg_dir}:${PKG_CONFIG_PATH}"
else
   __qruov_env_pkg_path="${__qruov_env_pkg_dir}"
fi

PKG_CONFIG_PATH="$__qruov_env_pkg_path"
export PKG_CONFIG_PATH
echo "export PKG_CONFIG_PATH=\"$__qruov_env_pkg_path\""

unset __qruov_env_self __qruov_env_local __qruov_env_uname \
   __qruov_env_search __qruov_env_os_note __qruov_env_prefix \
   __qruov_env_chosen __qruov_env_pkg_dir __qruov_env_pkg_path __p
unset -f __qruov_env_probe 2>/dev/null

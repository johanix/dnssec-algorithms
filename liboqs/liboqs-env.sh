#!/bin/sh
# liboqs-env.sh — set up CGO build environment for dnssec-algorithms
# and the tdns binaries that depend on it.
#
# Detects the OS, copies the matching pkg-config template into place
# (if liboqs-go.pc is missing), and prints export statements for the
# environment variables Go's cgo needs to find liboqs at build time.
#
# Usage:
#   . liboqs/liboqs-env.sh              # source: sets vars in current shell
#   eval "$(liboqs/liboqs-env.sh)"      # equivalent
#   liboqs/liboqs-env.sh                # bare: just prints what to export
#
# After sourcing, you can `make` the tdns binaries in cmdv2/ as usual.
#
# Supports:
#   - NetBSD with pkgsrc liboqs       (/usr/pkg/{include,lib})
#   - macOS with MacPorts liboqs      (/opt/local/{include,lib})
#   - Linux (Debian/Ubuntu)           coming tomorrow
#
# Idempotent — safe to source multiple times.

# Locate the directory holding this script (works when sourced too).
__libqs_env_self=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)
if [ -z "$__libqs_env_self" ]; then
   # Fallback for /bin/sh which may not support BASH_SOURCE: caller
   # must have $0 resolvable, or cwd must be the liboqs/ directory.
   __libqs_env_self=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
fi
__libqs_env_pkgconfig="${__libqs_env_self}/pkgconfig"
__libqs_env_pc="${__libqs_env_pkgconfig}/liboqs-go.pc"

# Pick a template based on the OS.
__libqs_env_uname=$(uname -s 2>/dev/null || echo unknown)
case "$__libqs_env_uname" in
   NetBSD)
      __libqs_env_template="${__libqs_env_pkgconfig}/liboqs-go.pc.netbsd-pkgsrc"
      __libqs_env_cgo_ldflags="-lcrypto"
      ;;
   Darwin)
      __libqs_env_template="${__libqs_env_pkgconfig}/liboqs-go.pc.macos-dev"
      # macOS MacPorts liboqs.dylib already pulls in libcrypto.3.dylib
      # via NEEDED entries; we don't need to mention it.
      __libqs_env_cgo_ldflags=""
      ;;
   Linux)
      echo "# liboqs-env.sh: Linux template not yet shipped — please" >&2
      echo "# write a liboqs-go.pc by hand for now." >&2
      return 1 2>/dev/null || exit 1
      ;;
   *)
      echo "# liboqs-env.sh: unsupported OS '$__libqs_env_uname'" >&2
      return 1 2>/dev/null || exit 1
      ;;
esac

# Install the template if liboqs-go.pc is missing.
if [ ! -f "$__libqs_env_pc" ]; then
   if [ ! -f "$__libqs_env_template" ]; then
      echo "# liboqs-env.sh: template not found: $__libqs_env_template" >&2
      return 1 2>/dev/null || exit 1
   fi
   cp "$__libqs_env_template" "$__libqs_env_pc"
   echo "# liboqs-env.sh: installed $__libqs_env_pc from $(basename "$__libqs_env_template")" >&2
fi

# Compose the env exports. Print them so the caller can `eval` if
# they didn't source, and also set them in this shell so sourcing
# Just Works.
if [ -n "$PKG_CONFIG_PATH" ]; then
   __libqs_env_pkg_path="${__libqs_env_pkgconfig}:${PKG_CONFIG_PATH}"
else
   __libqs_env_pkg_path="${__libqs_env_pkgconfig}"
fi

PKG_CONFIG_PATH="$__libqs_env_pkg_path"
export PKG_CONFIG_PATH
echo "export PKG_CONFIG_PATH=\"$__libqs_env_pkg_path\""

if [ -n "$__libqs_env_cgo_ldflags" ]; then
   CGO_LDFLAGS="$__libqs_env_cgo_ldflags"
   export CGO_LDFLAGS
   echo "export CGO_LDFLAGS=\"$__libqs_env_cgo_ldflags\""
fi

# Clean up local vars (when sourced).
unset __libqs_env_self __libqs_env_pkgconfig __libqs_env_pc \
   __libqs_env_uname __libqs_env_template __libqs_env_cgo_ldflags \
   __libqs_env_pkg_path

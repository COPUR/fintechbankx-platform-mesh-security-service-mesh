# shellcheck shell=bash
# Content pinning of Helm chart archives (deploy/cert-manager/CHART_DIGESTS).
# Sourced by scripts/istio/install-mesh.sh and
# scripts/ci/validate-jetstack-charts.sh; defines functions only.
#
# CHART_DIGESTS format (sha256sum -c): "<64 lower-case hex>  <archive name>",
# '#' comments and blank lines ignored. The literal PLACEHOLDER marks a digest
# nobody has computed yet; it never verifies.

CHART_DIGEST_PLACEHOLDER=PLACEHOLDER

# chart_digest_entry <digests-file> <archive-name>
# Prints the digest field of the single line naming the archive; fails when
# there is no such line or more than one.
chart_digest_entry() {
  awk -v n="$2" '
    /^[[:space:]]*(#|$)/ { next }
    NF == 2 && ($2 == n || $2 == "*" n) { print $1; c++ }
    END { exit c == 1 ? 0 : 1 }
  ' "$1"
}

# check_chart_digests_file <digests-file> <allow-placeholder:0|1> <archive-name>...
# Exactly one line per archive and no other line; every digest is a sha256.
# With allow-placeholder=1 a PLACEHOLDER digest is reported as a warning only.
check_chart_digests_file() {
  local file="$1" allow="$2" name digest entries rc=0
  shift 2
  if [ ! -f "$file" ]; then
    echo "chart digests: $file is missing" >&2
    return 1
  fi
  for name in "$@"; do
    if ! digest="$(chart_digest_entry "$file" "$name")"; then
      echo "chart digests: $file needs exactly one line for $name" >&2
      rc=1
    elif [ "$digest" = "$CHART_DIGEST_PLACEHOLDER" ]; then
      if [ "$allow" = 1 ]; then
        echo "chart digests: WARNING $name has no sha256 yet ($CHART_DIGEST_PLACEHOLDER in $file); the archive is NOT verified" >&2
      else
        echo "chart digests: $name has no sha256 ($CHART_DIGEST_PLACEHOLDER in $file); an operator must pull it on a trusted network, hash it and commit the digest" >&2
        rc=1
      fi
    elif ! [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
      echo "chart digests: $name: '$digest' in $file is not a sha256 (64 lower-case hex)" >&2
      rc=1
    fi
  done
  entries="$(grep -cvE '^[[:space:]]*(#|$)' "$file" || true)"
  if [ "$entries" != "$#" ]; then
    echo "chart digests: $file has $entries entries, expected $# ($*)" >&2
    rc=1
  fi
  return "$rc"
}

# sha256_check: sha256sum -c of "<digest>  <name>" lines on stdin, in the
# current directory (shasum on hosts without coreutils).
sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --strict -c -
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 --strict -c -
  else
    echo "chart digests: neither sha256sum nor shasum is installed" >&2
    return 1
  fi
}

# sha256_of <file>: prints the file's sha256 (64 lower-case hex).
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    echo "chart digests: neither sha256sum nor shasum is installed" >&2
    return 1
  fi
}

# verify_or_report_chart_archive <digests-file> <archive-path>
# CI only. A committed sha256 must match (mismatch fails). A PLACEHOLDER is
# reported instead: one greppable line "CHART_DIGEST <archive> <sha256>" that
# an operator copies into the digests file after a second, independent pull.
verify_or_report_chart_archive() {
  local file="$1" archive="$2" name digest actual
  name="$(basename "$archive")"
  digest="$(chart_digest_entry "$file" "$name")" || {
    echo "chart digests: $file needs exactly one line for $name" >&2
    return 1
  }
  if [ "$digest" != "$CHART_DIGEST_PLACEHOLDER" ]; then
    verify_chart_archive "$file" "$archive"
    return
  fi
  [ -f "$archive" ] || { echo "chart digests: $archive not found" >&2; return 1; }
  actual="$(sha256_of "$archive")" || return 1
  echo "CHART_DIGEST $name $actual"
  echo "chart digests: WARNING $name is NOT verified ($CHART_DIGEST_PLACEHOLDER in $file); after a second, independent pull agrees, commit: $actual  $name" >&2
}

# verify_chart_archive <digests-file> <archive-path>
# The downloaded archive must match its committed sha256 before anything uses it.
verify_chart_archive() {
  local file="$1" archive="$2" name digest
  name="$(basename "$archive")"
  if ! digest="$(chart_digest_entry "$file" "$name")" || ! [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "chart digests: no sha256 for $name in $file; refusing to use the archive" >&2
    return 1
  fi
  if [ ! -f "$archive" ]; then
    echo "chart digests: $archive not found" >&2
    return 1
  fi
  if ! (cd "$(dirname "$archive")" && printf '%s  %s\n' "$digest" "$name" | sha256_check); then
    echo "chart digests: $name does not match its sha256 in $file; refusing to use it" >&2
    return 1
  fi
}

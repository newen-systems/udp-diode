#!/usr/bin/env bash
# VERSION handling shared by the workflows and tests/release.sh.
#   release.sh check <version>         exit 1 unless <version> is valid semver 2.0
#   release.sh decide <ref> <version>  release=true for refs/tags/vX.Y.Z when it matches <version> (the VERSION file);
#                                      release=false for any other ref; exit 1 for a v-tag that is not X.Y.Z or does not match
set -euo pipefail
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
release='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
case "${1:-}" in
  check) [[ ${2:-} =~ $semver ]] || { echo "VERSION '${2:-}' is not valid semver" >&2; exit 1; } ;;
  decide)
    ref=${2:-} version=${3:-}
    if [[ $ref != refs/tags/v* ]]; then echo release=false; exit 0; fi
    tag=${ref#refs/tags/v}
    [[ $tag =~ $release ]] || { echo "tag v$tag is not vX.Y.Z" >&2; exit 1; }
    [[ $tag == "$version" ]] || { echo "tag v$tag does not match VERSION $version: set VERSION, merge, then tag that commit" >&2; exit 1; }
    echo release=true ;;
  *) sed -n 2,5p "$0" >&2; exit 2 ;;
esac

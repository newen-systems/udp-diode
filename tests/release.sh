#!/usr/bin/env bash
# Dry run of the release decision: no tag is created.
set -uo pipefail
cd "$(dirname "$0")/.."
r=.github/scripts/release.sh
fails=0
want() { local name=$1 expect=$2; shift 2; local got; got=$("$@" 2>/dev/null); [[ $got == "$expect" ]] && echo "PASS $name" || { echo "FAIL $name: got '$got'"; fails=$((fails + 1)); }; }
bad() { local name=$1; shift; if "$@" >/dev/null 2>&1; then echo "FAIL $name"; fails=$((fails + 1)); else echo "PASS $name"; fi; }
ok() { local name=$1; shift; if "$@" >/dev/null 2>&1; then echo "PASS $name"; else echo "FAIL $name"; fails=$((fails + 1)); fi; }
ok "VERSION file is valid semver" $r check "$(cat VERSION)"
for v in 0.1.0 1.2.3 0.1.0-dev 1.0.0-rc.1 1.0.0+build.5; do ok "semver accepts $v" $r check $v; done
for v in "" 1.0 v1.0.0 01.0.0 1.0.0- dev; do bad "semver rejects '$v'" $r check "$v"; done
want "a push to main does not release" release=false $r decide refs/heads/main 0.1.0
want "a pull request does not release" release=false $r decide refs/pull/7/merge 0.1.0
want "tag v0.1.0 with VERSION 0.1.0 releases" release=true $r decide refs/tags/v0.1.0 0.1.0
bad "tag v0.2.2 with VERSION 0.1.0 fails" $r decide refs/tags/v0.2.2 0.1.0
bad "tag v0.3.0-rc.1 fails" $r decide refs/tags/v0.3.0-rc.1 0.3.0-rc.1
bad "tag v1.0 fails" $r decide refs/tags/v1.0 1.0
echo "failures: $fails"
exit $((fails > 0))

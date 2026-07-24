#!/usr/bin/env bash
# ASI self-test: run both bundled examples and assert the expected dead
# functions are found. Exercises the pytrace (Python) and gcov (C) backends.
#
#   bash tests/selftest.sh
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"

fail=0

# A function matches NAME if its final dotted component equals NAME exactly
# (so "used_method" does not accidentally match "Helper.unused_method").
_leaf_in_dead() {
    python3 -c "import json,sys; d=json.load(open('$1')); \
        sys.exit(0 if any(f['name'].split('.')[-1]=='$2' for f in d['dead']) else 1)"
}

check() {
    # check <report.json> <expected-dead-name> ...
    local report="$1"; shift
    for name in "$@"; do
        if ! _leaf_in_dead "$report" "$name"; then
            echo "  MISSING expected dead function: $name"
            fail=1
        fi
    done
}

not_dead() {
    local report="$1"; shift
    for name in "$@"; do
        if _leaf_in_dead "$report" "$name"; then
            echo "  FALSE POSITIVE (live fn reported dead): $name"
            fail=1
        fi
    done
}

echo "== python_demo (pytrace backend) =="
python3 -m asi run -c examples/python_demo/asi.json >/dev/null 2>&1
R=examples/python_demo/asi_report/report.json
check "$R" unused_multiply unused_power unused_method
not_dead "$R" add sub used_method

echo "== c_demo (gcov backend) =="
if command -v gcc >/dev/null 2>&1; then
    python3 -m asi run -c examples/c_demo/asi.json >/dev/null 2>&1
    R=examples/c_demo/asi_report/report.json
    check "$R" mul dead_mod dead_negate
    not_dead "$R" add sub main
else
    echo "  (skipped: gcc not available)"
fi

echo "== refactor: comment-only (python_demo) =="
python3 -m asi refactor -c examples/python_demo/asi.json --comment-only \
    --out "$HERE/.selftest_rf" >/dev/null 2>&1
if python3 - "$HERE/.selftest_rf/mathlib.py" <<'PY'
import sys
src = open(sys.argv[1]).read()
ns = {}
exec(compile(src, sys.argv[1], "exec"), ns)   # must still compile
# dead functions must no longer be defined; live ones must remain
ok = ("unused_multiply" not in ns) and ("unused_power" not in ns) \
     and ("add" in ns) and ("sub" in ns)
sys.exit(0 if ok else 1)
PY
then
    echo "  comment-only output valid; dead removed, live kept"
else
    echo "  FAILED: comment-only refactor output wrong"
    fail=1
fi

echo "== refactor: LLM plumbing via mock provider (python_demo) =="
if ASI_LLM_PROVIDER=mock python3 -m asi refactor -c examples/python_demo/asi.json \
    --out "$HERE/.selftest_rf_llm" >/dev/null 2>&1 \
    && python3 -c "ns={}; exec(open('$HERE/.selftest_rf_llm/mathlib.py').read(), ns); \
import sys; sys.exit(0 if 'unused_multiply' not in ns and 'add' in ns else 1)"; then
    echo "  mock LLM refactor produced valid output"
else
    echo "  FAILED: mock LLM refactor path"
    fail=1
fi
rm -rf "$HERE/.selftest_rf" "$HERE/.selftest_rf_llm"

if [ "$fail" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SELFTEST FAILED"
fi
exit "$fail"

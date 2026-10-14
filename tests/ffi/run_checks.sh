#!/bin/sh
# run_checks.sh <luajit> <module.lua> [slices] [jobs]: runs check.lua's layout and declaration
# checks over a generated module in parallel slices (one LuaJIT state each) and sums them up.
set -eu
LUAJIT=$1
MODULE=$2
SLICES=${3:-256}
JOBS=${4:-16}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$(mktemp -d)}
for what in layouts decls; do
    seq 1 "$SLICES" | xargs -P "$JOBS" -I{} sh -c "\"$LUAJIT\" \"$HERE/check.lua\" $what \"$MODULE\" {} $SLICES > \"$OUT/$what.{}.txt\" 2>&1 || echo \"$what slice {} exited \$?\" >> \"$OUT/$what.{}.txt\""
    cat "$OUT"/$what.*.txt | awk -v w=$what '
        $1 == w && $2 == "ok" { ok += $3; fail += $5; if (NF >= 7) members += $7 }
        $1 == "REASON" { r[$2] += $3 }
        $1 == "FAIL" && shown < 20 { print; shown++ }
        / exited / { print }
        END { printf "%s: ok %d fail %d", w, ok, fail; if (members) printf " (members checked %d)", members; printf "\n"; for (k in r) printf "  %s %d\n", k, r[k] }'
done
echo "outputs in $OUT"

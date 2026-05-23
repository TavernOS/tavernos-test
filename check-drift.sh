set -uo pipefail

echo "═══ shared marketing HTML drift check ═══"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR"
INNER_STATIC="$SCRIPT_DIR/../tavernos/web/static"

if [ ! -d "$INNER_STATIC" ]; then
  echo "ABORT: inner static dir not found at $INNER_STATIC" >&2
  echo "  (expected tavernos/ as sibling of tavernos-test/)" >&2
  exit 2
fi

SHARED="access.html alpha-guide.html alpha-self-test.html apply.html index.html"

NORMALIZE='rel="canonical"'

drift=0
checked=0
for b in $SHARED; do
  inner="$INNER_STATIC/$b"
  test_f="$TEST_DIR/$b"
  if [ ! -f "$inner" ]; then
    echo "  ! $b: missing in inner ($inner) — not a shared file anymore?"
    drift=1
    continue
  fi
  if [ ! -f "$test_f" ]; then
    echo "  ! $b: missing in test ($test_f)"
    drift=1
    continue
  fi
  checked=$((checked + 1))
  if diff -q <(grep -v "$NORMALIZE" "$inner") <(grep -v "$NORMALIZE" "$test_f") >/dev/null 2>&1; then
    echo "  ✓ $b: in sync (modulo canonical)"
  else
    echo "  ✗ $b: DRIFT — inner and test disagree (beyond the canonical link)"
    drift=1
  fi
done

echo "─── checked $checked shared files ───"
if [ "$drift" -ne 0 ]; then
  echo "✗ DRIFT DETECTED. Reconcile before deploying."
  echo "  To see what differs on a file:  diff <(grep -v 'rel=\"canonical\"' tavernos/web/static/<f>) <(grep -v 'rel=\"canonical\"' tavernos-test/<f>)"
  exit 1
fi
echo "✓ all shared HTML in sync — safe to deploy."
exit 0

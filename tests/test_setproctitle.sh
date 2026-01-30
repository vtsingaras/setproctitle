#!/bin/bash
#
# Functional tests for setproctitle
# Must be run as root
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SETPROCTITLE="${SCRIPT_DIR}/../src/setproctitle"
PASSED=0
FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

get_cmdline() {
    local pid=$1
    tr '\0' ' ' < /proc/$pid/cmdline | sed 's/ *$//'
}

cleanup() {
    log_info "Cleaning up background processes..."
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
}

trap cleanup EXIT

# Check prerequisites
log_info "Checking prerequisites..."

if [[ $EUID -ne 0 ]]; then
    echo "Error: This test script must be run as root"
    exit 1
fi

if [[ ! -x "$SETPROCTITLE" ]]; then
    echo "Error: setproctitle binary not found at $SETPROCTITLE"
    echo "Please build the project first: make"
    exit 1
fi

log_info "Using setproctitle binary: $SETPROCTITLE"
echo

# Test 1: Basic title change
echo "========================================"
log_info "Test 1: Basic title change"
echo "========================================"

sleep 1000 &
SLEEP_PID=$!
ORIGINAL_CMDLINE=$(get_cmdline $SLEEP_PID)
log_info "Started sleep process with PID $SLEEP_PID"
log_info "Original cmdline: '$ORIGINAL_CMDLINE'"

NEW_TITLE="test"
log_info "Setting title to: '$NEW_TITLE'"
$SETPROCTITLE -p $SLEEP_PID -t "$NEW_TITLE"

NEW_CMDLINE=$(get_cmdline $SLEEP_PID)
log_info "New cmdline: '$NEW_CMDLINE'"

if [[ "$NEW_CMDLINE" == "$NEW_TITLE" ]]; then
    log_pass "Basic title change works"
else
    log_fail "Basic title change failed (expected '$NEW_TITLE', got '$NEW_CMDLINE')"
fi

kill $SLEEP_PID 2>/dev/null || true
wait $SLEEP_PID 2>/dev/null || true
echo

# Test 2: Title with spaces
echo "========================================"
log_info "Test 2: Title with spaces"
echo "========================================"

sleep 1000 &
SLEEP_PID=$!
log_info "Started sleep process with PID $SLEEP_PID"

NEW_TITLE="a b"
log_info "Setting title to: '$NEW_TITLE'"
$SETPROCTITLE -p $SLEEP_PID -t "$NEW_TITLE"

NEW_CMDLINE=$(get_cmdline $SLEEP_PID)
log_info "New cmdline: '$NEW_CMDLINE'"

if [[ "$NEW_CMDLINE" == "$NEW_TITLE" ]]; then
    log_pass "Title with spaces works"
else
    log_fail "Title with spaces failed (expected '$NEW_TITLE', got '$NEW_CMDLINE')"
fi

kill $SLEEP_PID 2>/dev/null || true
wait $SLEEP_PID 2>/dev/null || true
echo

# Test 3: Title too long without --force (should fail)
echo "========================================"
log_info "Test 3: Title too long without --force"
echo "========================================"

sleep 1000 &
SLEEP_PID=$!
ORIGINAL_CMDLINE=$(get_cmdline $SLEEP_PID)
ORIGINAL_LEN=${#ORIGINAL_CMDLINE}
log_info "Started sleep process with PID $SLEEP_PID"
log_info "Original cmdline: '$ORIGINAL_CMDLINE' (length: $ORIGINAL_LEN)"

# Create a title longer than the original
LONG_TITLE=$(printf 'x%.0s' $(seq 1 $((ORIGINAL_LEN + 10))))
log_info "Attempting to set title of length ${#LONG_TITLE} (without --force)"

if $SETPROCTITLE -p $SLEEP_PID -t "$LONG_TITLE" 2>&1; then
    log_fail "Should have rejected long title without --force"
else
    log_pass "Correctly rejected long title without --force"
fi

kill $SLEEP_PID 2>/dev/null || true
wait $SLEEP_PID 2>/dev/null || true
echo

# Test 4: Title too long with --force (should succeed)
echo "========================================"
log_info "Test 4: Title too long with --force"
echo "========================================"

sleep 1000 &
SLEEP_PID=$!
ORIGINAL_CMDLINE=$(get_cmdline $SLEEP_PID)
ORIGINAL_LEN=${#ORIGINAL_CMDLINE}
log_info "Started sleep process with PID $SLEEP_PID"
log_info "Original cmdline: '$ORIGINAL_CMDLINE' (length: $ORIGINAL_LEN)"

# Create a title longer than the original but not too long
LONG_TITLE=$(printf 'y%.0s' $(seq 1 $((ORIGINAL_LEN + 10))))
log_info "Setting title of length ${#LONG_TITLE} (with --force)"

if $SETPROCTITLE -p $SLEEP_PID -t "$LONG_TITLE" --force; then
    NEW_CMDLINE=$(get_cmdline $SLEEP_PID)
    log_info "New cmdline: '$NEW_CMDLINE'"
    if [[ "$NEW_CMDLINE" == "$LONG_TITLE" ]]; then
        log_pass "Long title with --force works"
    else
        log_fail "Long title with --force: mismatch (expected '$LONG_TITLE', got '$NEW_CMDLINE')"
    fi
else
    log_fail "Long title with --force was rejected"
fi

kill $SLEEP_PID 2>/dev/null || true
wait $SLEEP_PID 2>/dev/null || true
echo

# Test 5: Invalid PID
echo "========================================"
log_info "Test 5: Invalid PID"
echo "========================================"

log_info "Attempting to set title for non-existent PID 999999"
if $SETPROCTITLE -p 999999 -t "test" 2>&1; then
    log_fail "Should have failed for invalid PID"
else
    log_pass "Correctly failed for invalid PID"
fi
echo

# Test 6: Missing arguments
echo "========================================"
log_info "Test 6: Missing arguments"
echo "========================================"

log_info "Running without arguments"
if $SETPROCTITLE 2>&1; then
    log_fail "Should have failed without arguments"
else
    log_pass "Correctly failed without arguments"
fi
echo

# Test 7: Long options
echo "========================================"
log_info "Test 7: Long options (--pid, --title)"
echo "========================================"

sleep 1000 &
SLEEP_PID=$!
log_info "Started sleep process with PID $SLEEP_PID"

NEW_TITLE="long"
log_info "Setting title using long options"
$SETPROCTITLE --pid $SLEEP_PID --title "$NEW_TITLE"

NEW_CMDLINE=$(get_cmdline $SLEEP_PID)
log_info "New cmdline: '$NEW_CMDLINE'"

if [[ "$NEW_CMDLINE" == "$NEW_TITLE" ]]; then
    log_pass "Long options work"
else
    log_fail "Long options failed (expected '$NEW_TITLE', got '$NEW_CMDLINE')"
fi

kill $SLEEP_PID 2>/dev/null || true
wait $SLEEP_PID 2>/dev/null || true
echo

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi

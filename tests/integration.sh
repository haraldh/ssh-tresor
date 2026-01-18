#!/usr/bin/env bash
#
# Integration test for ssh-tresor multi-key support
#
# This script:
# 1. Starts a fresh ssh-agent
# 2. Creates test SSH keys
# 3. Tests encrypt/decrypt with single and multiple keys
# 4. Tests add-key and remove-key operations
# 5. Tests list-slots
# 6. Cleans up all temporary files and processes

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Temporary directory for test artifacts
TEST_DIR=""
AGENT_PID=""
SSH_AUTH_SOCK_BACKUP="${SSH_AUTH_SOCK:-}"

cleanup() {
    echo ""
    echo "Cleaning up..."

    # Kill our ssh-agent if we started one
    if [[ -n "$AGENT_PID" ]]; then
        kill "$AGENT_PID" 2>/dev/null || true
    fi

    # Restore original SSH_AUTH_SOCK
    if [[ -n "$SSH_AUTH_SOCK_BACKUP" ]]; then
        export SSH_AUTH_SOCK="$SSH_AUTH_SOCK_BACKUP"
    else
        unset SSH_AUTH_SOCK 2>/dev/null || true
    fi

    # Remove temporary directory
    if [[ -n "$TEST_DIR" && -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi

    echo "Cleanup complete."
}

trap cleanup EXIT

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++)) || true
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++)) || true
}

run_test() {
    local name="$1"
    shift
    ((TESTS_RUN++)) || true

    # Run test in subshell to capture failures without exiting
    if (set +e; "$@"); then
        log_pass "$name"
    else
        log_fail "$name"
    fi
}

# Find the ssh-tresor binary
find_binary() {
    local binary=""

    # Check for release build first, then debug
    if [[ -x "./target/release/ssh-tresor" ]]; then
        binary="./target/release/ssh-tresor"
    elif [[ -x "./target/debug/ssh-tresor" ]]; then
        binary="./target/debug/ssh-tresor"
    else
        echo "Error: ssh-tresor binary not found. Run 'cargo build' first." >&2
        exit 1
    fi

    echo "$binary"
}

# Setup test environment
setup() {
    log_info "Setting up test environment..."

    # Create temporary directory
    TEST_DIR=$(mktemp -d)
    log_info "Test directory: $TEST_DIR"

    # Start a fresh ssh-agent
    log_info "Starting ssh-agent..."
    eval "$(ssh-agent -s)" > /dev/null
    AGENT_PID="$SSH_AGENT_PID"
    log_info "SSH agent started with PID $AGENT_PID"

    # Create test keys (without passphrases for testing)
    log_info "Creating test SSH keys..."
    ssh-keygen -t ed25519 -f "$TEST_DIR/key1" -N "" -C "test-key-1" -q
    ssh-keygen -t ed25519 -f "$TEST_DIR/key2" -N "" -C "test-key-2" -q
    ssh-keygen -t ed25519 -f "$TEST_DIR/key3" -N "" -C "test-key-3" -q

    # Add keys to agent
    log_info "Adding keys to ssh-agent..."
    ssh-add "$TEST_DIR/key1" 2>/dev/null
    ssh-add "$TEST_DIR/key2" 2>/dev/null
    ssh-add "$TEST_DIR/key3" 2>/dev/null

    # Get fingerprints
    KEY1_FP=$(ssh-keygen -lf "$TEST_DIR/key1.pub" | awk '{print $2}')
    KEY2_FP=$(ssh-keygen -lf "$TEST_DIR/key2.pub" | awk '{print $2}')
    KEY3_FP=$(ssh-keygen -lf "$TEST_DIR/key3.pub" | awk '{print $2}')

    log_info "Key 1 fingerprint: $KEY1_FP"
    log_info "Key 2 fingerprint: $KEY2_FP"
    log_info "Key 3 fingerprint: $KEY3_FP"

    # Create test data
    echo "Hello, this is secret data for testing ssh-tresor!" > "$TEST_DIR/plaintext.txt"

    log_info "Setup complete."
    echo ""
}

# Test: list-keys shows all keys
test_list_keys() {
    local output
    output=$("$BINARY" list-keys)

    [[ "$output" == *"test-key-1"* ]] && \
    [[ "$output" == *"test-key-2"* ]] && \
    [[ "$output" == *"test-key-3"* ]]
}

# Test: encrypt with single key and decrypt
test_single_key_encrypt_decrypt() {
    "$BINARY" encrypt -k "$KEY1_FP" < "$TEST_DIR/plaintext.txt" > "$TEST_DIR/tresor1.bin"
    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor1.bin")
    [[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]]
}

# Test: encrypt with default key (first available)
test_default_key_encrypt_decrypt() {
    "$BINARY" encrypt < "$TEST_DIR/plaintext.txt" > "$TEST_DIR/tresor_default.bin"
    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor_default.bin")
    [[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]]
}

# Test: encrypt with armored output
test_armored_output() {
    "$BINARY" encrypt -a -k "$KEY1_FP" < "$TEST_DIR/plaintext.txt" > "$TEST_DIR/tresor1.armor"

    # Check armor headers
    grep -q "BEGIN SSH TRESOR" "$TEST_DIR/tresor1.armor" && \
    grep -q "END SSH TRESOR" "$TEST_DIR/tresor1.armor" && \

    # Decrypt armored tresor
    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor1.armor")
    [[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]]
}

# Test: encrypt with multiple keys
test_multi_key_encrypt() {
    "$BINARY" encrypt -k "$KEY1_FP" -k "$KEY2_FP" -k "$KEY3_FP" \
        < "$TEST_DIR/plaintext.txt" > "$TEST_DIR/tresor_multi.bin"

    # Verify it created a valid tresor
    [[ -s "$TEST_DIR/tresor_multi.bin" ]]
}

# Test: list-slots shows all keys
test_list_slots_multi() {
    local output
    output=$("$BINARY" list-slots < "$TEST_DIR/tresor_multi.bin")

    [[ "$output" == *"3 key slot"* ]] && \
    [[ "$output" == *"AVAILABLE"* ]]
}

# Test: decrypt multi-key tresor with key1
test_decrypt_multi_with_key1() {
    # Remove key2 and key3 from agent temporarily
    ssh-add -d "$TEST_DIR/key2.pub" 2>/dev/null
    ssh-add -d "$TEST_DIR/key3.pub" 2>/dev/null

    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor_multi.bin")
    local result=$([[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]] && echo "ok" || echo "fail")

    # Re-add keys
    ssh-add "$TEST_DIR/key2" 2>/dev/null
    ssh-add "$TEST_DIR/key3" 2>/dev/null

    [[ "$result" == "ok" ]]
}

# Test: decrypt multi-key tresor with key2
test_decrypt_multi_with_key2() {
    # Remove key1 and key3 from agent temporarily
    ssh-add -d "$TEST_DIR/key1.pub" 2>/dev/null
    ssh-add -d "$TEST_DIR/key3.pub" 2>/dev/null

    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor_multi.bin")
    local result=$([[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]] && echo "ok" || echo "fail")

    # Re-add keys
    ssh-add "$TEST_DIR/key1" 2>/dev/null
    ssh-add "$TEST_DIR/key3" 2>/dev/null

    [[ "$result" == "ok" ]]
}

# Test: decrypt multi-key tresor with key3
test_decrypt_multi_with_key3() {
    # Remove key1 and key2 from agent temporarily
    ssh-add -d "$TEST_DIR/key1.pub" 2>/dev/null
    ssh-add -d "$TEST_DIR/key2.pub" 2>/dev/null

    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor_multi.bin")
    local result=$([[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]] && echo "ok" || echo "fail")

    # Re-add keys
    ssh-add "$TEST_DIR/key1" 2>/dev/null
    ssh-add "$TEST_DIR/key2" 2>/dev/null

    [[ "$result" == "ok" ]]
}

# Test: add-key to tresor
test_add_key() {
    # Start with single-key tresor
    "$BINARY" encrypt -k "$KEY1_FP" < "$TEST_DIR/plaintext.txt" > "$TEST_DIR/tresor_single.bin"

    # Add key2
    "$BINARY" add-key -k "$KEY2_FP" < "$TEST_DIR/tresor_single.bin" > "$TEST_DIR/tresor_added.bin"

    # Verify it now has 2 slots
    local output
    output=$("$BINARY" list-slots < "$TEST_DIR/tresor_added.bin")
    [[ "$output" == *"2 key slot"* ]]
}

# Test: decrypt after add-key with new key
test_decrypt_after_add_key() {
    # Remove key1 from agent
    ssh-add -d "$TEST_DIR/key1.pub" 2>/dev/null

    # Should be able to decrypt with key2
    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor_added.bin")
    local result=$([[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]] && echo "ok" || echo "fail")

    # Re-add key1
    ssh-add "$TEST_DIR/key1" 2>/dev/null

    [[ "$result" == "ok" ]]
}

# Test: remove-key from tresor
test_remove_key() {
    # Start with the tresor that has 2 keys
    "$BINARY" remove-key -k "$KEY1_FP" < "$TEST_DIR/tresor_added.bin" > "$TEST_DIR/tresor_removed.bin"

    # Verify it now has 1 slot
    local output
    output=$("$BINARY" list-slots < "$TEST_DIR/tresor_removed.bin")
    [[ "$output" == *"1 key slot"* ]]
}

# Test: decrypt after remove-key with remaining key
test_decrypt_after_remove_key() {
    local decrypted
    decrypted=$("$BINARY" decrypt < "$TEST_DIR/tresor_removed.bin")
    [[ "$decrypted" == "$(cat "$TEST_DIR/plaintext.txt")" ]]
}

# Test: cannot remove last key
test_cannot_remove_last_key() {
    # Try to remove the only key - should fail
    if "$BINARY" remove-key -k "$KEY2_FP" < "$TEST_DIR/tresor_removed.bin" > /dev/null 2>&1; then
        return 1  # Should have failed
    else
        return 0  # Expected failure
    fi
}

# Test: cannot add duplicate key
test_cannot_add_duplicate_key() {
    if "$BINARY" add-key -k "$KEY1_FP" < "$TEST_DIR/tresor_single.bin" > /dev/null 2>&1; then
        return 1  # Should have failed
    else
        return 0  # Expected failure
    fi
}

# Test: no matching slot error
test_no_matching_slot() {
    # Create tresor with key1
    "$BINARY" encrypt -k "$KEY1_FP" < "$TEST_DIR/plaintext.txt" > "$TEST_DIR/tresor_key1only.bin"

    # Remove all keys from agent
    ssh-add -D 2>/dev/null

    # Add only key2 (which is not in the tresor)
    ssh-add "$TEST_DIR/key2" 2>/dev/null

    # Try to decrypt - should fail
    local result
    if "$BINARY" decrypt < "$TEST_DIR/tresor_key1only.bin" > /dev/null 2>&1; then
        result=1  # Should have failed
    else
        result=0  # Expected failure
    fi

    # Re-add all keys
    ssh-add "$TEST_DIR/key1" 2>/dev/null
    ssh-add "$TEST_DIR/key3" 2>/dev/null

    return $result
}

# Test: binary data roundtrip
test_binary_data() {
    # Create binary test data
    dd if=/dev/urandom of="$TEST_DIR/binary_data.bin" bs=1024 count=10 2>/dev/null

    # Encrypt and decrypt
    "$BINARY" encrypt -k "$KEY1_FP" < "$TEST_DIR/binary_data.bin" > "$TEST_DIR/tresor_binary.bin"
    "$BINARY" decrypt < "$TEST_DIR/tresor_binary.bin" > "$TEST_DIR/binary_data_decrypted.bin"

    # Compare
    diff -q "$TEST_DIR/binary_data.bin" "$TEST_DIR/binary_data_decrypted.bin" > /dev/null
}

# Test: large file
test_large_file() {
    # Create 1MB test data
    dd if=/dev/urandom of="$TEST_DIR/large_data.bin" bs=1024 count=1024 2>/dev/null

    # Encrypt and decrypt
    "$BINARY" encrypt -k "$KEY1_FP" < "$TEST_DIR/large_data.bin" > "$TEST_DIR/tresor_large.bin"
    "$BINARY" decrypt < "$TEST_DIR/tresor_large.bin" > "$TEST_DIR/large_data_decrypted.bin"

    # Compare
    diff -q "$TEST_DIR/large_data.bin" "$TEST_DIR/large_data_decrypted.bin" > /dev/null
}

# Test: empty file
test_empty_file() {
    touch "$TEST_DIR/empty.txt"

    "$BINARY" encrypt -k "$KEY1_FP" < "$TEST_DIR/empty.txt" > "$TEST_DIR/tresor_empty.bin"
    "$BINARY" decrypt < "$TEST_DIR/tresor_empty.bin" > "$TEST_DIR/empty_decrypted.txt"

    [[ ! -s "$TEST_DIR/empty_decrypted.txt" ]]
}

# Main test runner
main() {
    echo "========================================"
    echo "  ssh-tresor Integration Tests"
    echo "========================================"
    echo ""

    BINARY=$(find_binary)
    log_info "Using binary: $BINARY"
    echo ""

    setup

    echo "Running tests..."
    echo ""

    # Basic tests
    run_test "list-keys shows all test keys" test_list_keys
    run_test "single key encrypt/decrypt" test_single_key_encrypt_decrypt
    run_test "default key encrypt/decrypt" test_default_key_encrypt_decrypt
    run_test "armored output" test_armored_output

    # Multi-key tests
    run_test "multi-key encrypt" test_multi_key_encrypt
    run_test "list-slots shows all slots" test_list_slots_multi
    run_test "decrypt multi-key tresor with key1" test_decrypt_multi_with_key1
    run_test "decrypt multi-key tresor with key2" test_decrypt_multi_with_key2
    run_test "decrypt multi-key tresor with key3" test_decrypt_multi_with_key3

    # Key management tests
    run_test "add-key to tresor" test_add_key
    run_test "decrypt after add-key with new key" test_decrypt_after_add_key
    run_test "remove-key from tresor" test_remove_key
    run_test "decrypt after remove-key" test_decrypt_after_remove_key

    # Error handling tests
    run_test "cannot remove last key" test_cannot_remove_last_key
    run_test "cannot add duplicate key" test_cannot_add_duplicate_key
    run_test "no matching slot error" test_no_matching_slot

    # Data integrity tests
    run_test "binary data roundtrip" test_binary_data
    run_test "large file (1MB)" test_large_file
    run_test "empty file" test_empty_file

    echo ""
    echo "========================================"
    echo "  Test Results"
    echo "========================================"
    echo ""
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        exit 1
    fi
}

main "$@"

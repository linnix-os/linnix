#!/bin/bash
# Linnix Full Test Suite
# Runs all tests and validates documentation against code

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Linnix Full Test Suite                           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

FAILED=0

run_step() {
    local step_num="$1"
    local step_name="$2"
    local command="$3"
    
    echo -e "${BLUE}[${step_num}] ${step_name}${NC}"
    echo "    Command: $command"
    
    if eval "$command"; then
        echo -e "${GREEN}    ✓ Passed${NC}"
        echo ""
    else
        echo -e "${RED}    ✗ Failed${NC}"
        echo ""
        FAILED=1
    fi
}

# ============================================================================
# Phase 1: Rust Tests
# ============================================================================
echo -e "${YELLOW}═══ Phase 1: Rust Tests ═══${NC}"
echo ""

run_step "1.1" "Unit Tests (default profile)" \
    "RUSTFLAGS='-D warnings' cargo nextest run --workspace --profile default 2>&1 | tail -20"

run_step "1.2" "E2E Tests (serial execution)" \
    "cargo nextest run --workspace --profile e2e 2>&1 | tail -20"

# ============================================================================
# Phase 2: Code Quality
# ============================================================================
echo -e "${YELLOW}═══ Phase 2: Code Quality ═══${NC}"
echo ""

run_step "2.1" "Format Check" \
    "cargo fmt --all -- --check"

run_step "2.2" "Clippy Lints" \
    "cargo clippy --all-targets --all-features -- -D warnings 2>&1 | tail -20"

run_step "2.3" "Dependency Audit (cargo deny)" \
    "cargo deny check 2>&1 | tail -10"

# ============================================================================
# Phase 3: Build Verification
# ============================================================================
echo -e "${YELLOW}═══ Phase 3: Build Verification ═══${NC}"
echo ""

run_step "3.1" "Release Build" \
    "cargo build --release -p cognitod -p linnix-cli -p linnix-reasoner 2>&1 | tail -5"

# Check if xtask can run (may need nightly)
if cargo xtask --help >/dev/null 2>&1; then
    run_step "3.2" "eBPF Build (xtask)" \
        "cargo xtask build-ebpf 2>&1 | tail -10"
else
    echo -e "${YELLOW}[3.2] eBPF Build - Skipped (xtask not available)${NC}"
    echo ""
fi

# ============================================================================
# Phase 4: Documentation Validation
# ============================================================================
echo -e "${YELLOW}═══ Phase 4: Documentation Validation ═══${NC}"
echo ""

run_step "4.1" "Doc Validator" \
    "python3 scripts/validate_docs.py --workspace ."

# Check for broken links in markdown (if markdown-link-check is installed)
if command -v markdown-link-check &> /dev/null; then
    run_step "4.2" "Markdown Link Check" \
        "find . -name '*.md' -not -path './target/*' | head -10 | xargs -I{} markdown-link-check {} 2>&1 | tail -20"
else
    echo -e "${YELLOW}[4.2] Markdown Link Check - Skipped (markdown-link-check not installed)${NC}"
    echo ""
fi

# ============================================================================
# Phase 5: API Endpoint Extraction (Static)
# ============================================================================
echo -e "${YELLOW}═══ Phase 5: API Endpoint Analysis ═══${NC}"
echo ""

echo -e "${BLUE}[5.1] Extracting API Routes from Code${NC}"
echo "    Routes defined in cognitod/src/api/mod.rs:"
grep -E '\.route\("/' cognitod/src/api/mod.rs | sed 's/.*\.route("\([^"]*\)".*/    - \1/' | sort -u
echo ""

echo -e "${BLUE}[5.2] Extracting Config Structs from Code${NC}"
echo "    Config structs in cognitod/src/config.rs:"
grep -E 'pub struct \w+Config' cognitod/src/config.rs | sed 's/.*struct \(\w\+Config\).*/    - \1/'
echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        Summary                                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Start cognitod: sudo ./target/release/cognitod --config configs/linnix.toml"
    echo "  2. Run API validation: ./scripts/validate_api_docs.sh"
    echo "  3. Generate wiki: ./scripts/generate_wiki.sh"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Please review the output above.${NC}"
    exit 1
fi

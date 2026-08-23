#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOKS_DIR" ]; then
    echo "❌ Not a git repository"
    exit 1
fi

echo "📦 Installing git hooks..."

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🔍 Running pre-commit checks..."
echo ""

if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Not in repository root"
    exit 1
fi

echo "📝 Checking code formatting..."
if ! FMT_OUTPUT="$(cargo fmt --all -- --check 2>&1)"; then
    printf '%s\n' "$FMT_OUTPUT" | grep -v "^Warning:" | grep -v "^$" || true
    echo "❌ Format check failed. Run: cargo fmt --all"
    exit 1
fi
echo "✅ Format check passed"
echo ""

echo "🔧 Running clippy..."
if ! cargo clippy --all-targets --all-features -- -D warnings 2>&1 | tail -20; then
    echo "❌ Clippy failed"
    exit 1
fi
echo "✅ Clippy passed"
echo ""

echo "🧪 Running unit tests..."
if ! cargo nextest run --workspace --profile default 2>&1 | tail -10; then
    echo "❌ Tests failed"
    exit 1
fi
echo "✅ Tests passed"
echo ""

if command -v cargo-deny >/dev/null 2>&1; then
    echo "🛡️  Running cargo deny..."
    if ! cargo deny check 2>&1 | tail -5; then
        echo "❌ Cargo deny failed"
        exit 1
    fi
    echo "✅ Cargo deny passed"
    echo ""
fi

echo "✅ All pre-commit checks passed!"
echo ""
EOF

chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Git hooks installed successfully!"
echo ""
echo "The pre-commit hook will run:"
echo "  • cargo fmt --check"
echo "  • cargo clippy"
echo "  • cargo nextest run"
echo "  • cargo deny check (if installed)"
echo ""
echo "To skip hooks: git commit --no-verify"

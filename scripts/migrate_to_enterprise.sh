#!/bin/bash
set -e

ENTERPRISE_DIR="/home/parthshah/linnix-enterprise"
OSS_DIR="/home/parthshah/linnix-opensource"

echo "🚀 Starting migration to enterprise repo..."
echo "Enterprise dir: $ENTERPRISE_DIR"
echo ""

# Verify enterprise repo exists
if [ ! -d "$ENTERPRISE_DIR" ]; then
    echo "❌ Error: Enterprise repo not found at $ENTERPRISE_DIR"
    exit 1
fi

# Create directory structure in enterprise
echo "📁 Creating enterprise directory structure..."
cd "$ENTERPRISE_DIR"
mkdir -p models/{pytorch,gguf}
mkdir -p datasets/training
mkdir -p scripts/training
mkdir -p docs/training
mkdir -p notebooks
mkdir -p training-logs
echo "✅ Directories created"
echo ""

# Move large model files
echo "📦 Moving model files..."
cd "$OSS_DIR"

if [ -d "h200-distilled-model" ]; then
    echo "  - h200-distilled-model/ (PyTorch)"
    mv h200-distilled-model "$ENTERPRISE_DIR/models/pytorch/"
else
    echo "  ⚠ h200-distilled-model not found (may already be moved)"
fi

if [ -f "linnix-3b-distilled.gguf" ]; then
    echo "  - linnix-3b-distilled.gguf (5.8GB F16)"
    mv linnix-3b-distilled.gguf "$ENTERPRISE_DIR/models/gguf/"
else
    echo "  ⚠ linnix-3b-distilled.gguf not found"
fi

echo "✅ Models moved"
echo ""

# Move training data
echo "📊 Moving training datasets..."
if compgen -G "training_data*.json" > /dev/null; then
    mv training_data*.json "$ENTERPRISE_DIR/datasets/training/"
    echo "✅ Training data moved"
else
    echo "  ⚠ No training_data*.json files found"
fi

if compgen -G "runpod_migration_*" > /dev/null; then
    mv runpod_migration_*/ "$ENTERPRISE_DIR/training-logs/"
    echo "✅ Training logs moved"
else
    echo "  ⚠ No runpod_migration_* directories found"
fi
echo ""

# Move training scripts
echo "🔧 Moving training scripts..."
cd scripts
TRAINING_SCRIPTS=(
    "h200_premium_trainer.py"
    "distill_lora_to_3b.py"
    "distill_on_runpod.py"
    "monitor_h200_training.sh"
    "monitor_distillation.sh"
    "monitor_runpod_distillation.sh"
    "h200_premium_analysis.sh"
)

for script in "${TRAINING_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        echo "  - $script"
        mv "$script" "$ENTERPRISE_DIR/scripts/training/"
    fi
done
echo "✅ Training scripts moved"
echo ""

# Move notebooks
echo "📓 Moving training notebooks..."
cd ../notebooks
TRAINING_NOTEBOOKS=(
    "distill_model_on_runpod.ipynb"
    "distill_linnix_model.ipynb"
    "runpod_distillation_simple.ipynb"
)

for nb in "${TRAINING_NOTEBOOKS[@]}"; do
    if [ -f "$nb" ]; then
        echo "  - $nb"
        mv "$nb" "$ENTERPRISE_DIR/notebooks/"
    fi
done
echo "✅ Notebooks moved"
echo ""

# Move training docs
echo "📖 Moving training documentation..."
cd ../docs
if [ -f "runpod-distillation.md" ]; then
    mv runpod-distillation.md "$ENTERPRISE_DIR/docs/training/"
    echo "  - runpod-distillation.md"
fi

if [ -f "distillation-guide.md" ]; then
    mv distillation-guide.md "$ENTERPRISE_DIR/docs/training/"
    echo "  - distillation-guide.md"
fi
echo "✅ Documentation moved"
echo ""

# Summary
echo "🎉 Migration complete!"
echo ""
echo "Files remaining in OSS:"
cd "$OSS_DIR"
ls -lh serve_distilled_model.sh benchmark_distilled_model.sh .env.distilled linnix-3b-distilled-q5_k_m.gguf test_h200_model.py 2>/dev/null || true
echo ""
echo "Enterprise repo now contains:"
echo "  - PyTorch models: $ENTERPRISE_DIR/models/pytorch/"
echo "  - GGUF models: $ENTERPRISE_DIR/models/gguf/"
echo "  - Training data: $ENTERPRISE_DIR/datasets/training/"
echo "  - Training scripts: $ENTERPRISE_DIR/scripts/training/"
echo "  - Notebooks: $ENTERPRISE_DIR/notebooks/"
echo "  - Training logs: $ENTERPRISE_DIR/training-logs/"
echo ""
echo "Next steps:"
echo "  1. Verify files in enterprise repo"
echo "  2. Git commit in OSS: git rm --cached <moved files>"
echo "  3. Git add in enterprise: git add models/ datasets/ scripts/"
echo "  4. Consider hosting demo model externally (2.1GB is large for git)"

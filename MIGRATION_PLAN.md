# Migration Plan: Open Source ↔ Enterprise Split

## Files to Move to Enterprise

### Training Artifacts (Move to linnix-enterprise)

**Source**: `linnix-opensource/`
**Destination**: `linnix-enterprise/models/`

```bash
# Move H200 training artifacts
mv h200-distilled-model/ /home/parthshah/linnix-enterprise/models/
mv training_data_progress_*.json /home/parthshah/linnix-enterprise/datasets/training/
mv runpod_migration_*/ /home/parthshah/linnix-enterprise/training-logs/

# Move training notebooks
mv notebooks/distill_*.ipynb /home/parthshah/linnix-enterprise/notebooks/
mv notebooks/runpod_*.ipynb /home/parthshah/linnix-enterprise/notebooks/

# Move training scripts
mv scripts/h200_premium_trainer.py /home/parthshah/linnix-enterprise/scripts/
mv scripts/distill_*.py /home/parthshah/linnix-enterprise/scripts/
mv scripts/monitor_h200_training.sh /home/parthshah/linnix-enterprise/scripts/
mv scripts/monitor_distillation.sh /home/parthshah/linnix-enterprise/scripts/

# Move large GGUF models (keep demo model)
mv linnix-3b-distilled.gguf /home/parthshah/linnix-enterprise/models/  # F16 version
# Keep: linnix-3b-distilled-q5_k_m.gguf (2.1GB demo model)
```

### Training Documentation (Move to Enterprise)

**Source**: `linnix-opensource/docs/`
**Destination**: `linnix-enterprise/docs/`

```bash
mv docs/runpod-distillation.md /home/parthshah/linnix-enterprise/docs/
mv docs/distillation-guide.md /home/parthshah/linnix-enterprise/docs/
```

## Files to Keep in Open Source

### Inference/Demo Files (Keep in linnix-opensource)

✅ Keep these for community demos:

```
linnix-opensource/
├── serve_distilled_model.sh           # Generic llama.cpp server
├── benchmark_distilled_model.sh       # Performance testing
├── linnix-3b-distilled-q5_k_m.gguf   # 2.1GB demo model (or use Git LFS/external link)
├── test_h200_model.py                # Inference testing
├── .env.distilled                    # Demo config
├── linnix-reasoner/                  # Enhanced with process table ✅
└── scripts/
    └── deploy_distilled_model.sh     # Deployment helper
```

### Documentation (Keep in Open Source)

✅ Update these docs to reference enterprise:

```
linnix-opensource/
├── DISTILLED_MODEL_INTEGRATION.md    # Keep, add enterprise reference
├── PROCESS_NAMES_ENHANCEMENT.md      # Keep, pure OSS feature
├── QUICKSTART_PROCESS_NAMES.md       # Keep
├── H200_DISTILLATION_SUCCESS_REPORT.md  # Keep as case study, anonymize details
└── FEATURE_DISTRIBUTION.md           # Keep, explains split
```

## Migration Commands

### Step 1: Setup Enterprise Directories

```bash
cd /home/parthshah/linnix-enterprise

# Create directory structure
mkdir -p models/{pytorch,gguf}
mkdir -p datasets/training
mkdir -p scripts/training
mkdir -p docs/training
mkdir -p notebooks
mkdir -p training-logs
```

### Step 2: Move Training Artifacts

```bash
cd /home/parthshah/linnix-opensource

# Move model files
mv h200-distilled-model/* /home/parthshah/linnix-enterprise/models/pytorch/
mv linnix-3b-distilled.gguf /home/parthshah/linnix-enterprise/models/gguf/

# Move training data
mv training_data_progress_*.json /home/parthshah/linnix-enterprise/datasets/training/
mv runpod_migration_*/* /home/parthshah/linnix-enterprise/training-logs/

# Move scripts
mv scripts/h200_premium_trainer.py /home/parthshah/linnix-enterprise/scripts/training/
mv scripts/distill_lora_to_3b.py /home/parthshah/linnix-enterprise/scripts/training/
mv scripts/distill_on_runpod.py /home/parthshah/linnix-enterprise/scripts/training/
mv scripts/monitor_h200_training.sh /home/parthshah/linnix-enterprise/scripts/training/
mv scripts/monitor_distillation.sh /home/parthshah/linnix-enterprise/scripts/training/

# Move notebooks
mv notebooks/distill_*.ipynb /home/parthshah/linnix-enterprise/notebooks/
mv notebooks/runpod_*.ipynb /home/parthshah/linnix-enterprise/notebooks/

# Move docs
mv docs/runpod-distillation.md /home/parthshah/linnix-enterprise/docs/training/
mv docs/distillation-guide.md /home/parthshah/linnix-enterprise/docs/training/
```

### Step 3: Update Open Source Docs

```bash
# Update references in open source docs
cd /home/parthshah/linnix-opensource

# Add enterprise references to distillation success report
echo "
---
**Note**: The training artifacts, datasets, and full PyTorch models are available in [Linnix Enterprise](https://linnix.io/enterprise). The open-source version includes the quantized demo model and inference scripts.
" >> H200_DISTILLATION_SUCCESS_REPORT.md
```

### Step 4: Add Download Links for Demo Model

**Option A: Git LFS** (if model < 100MB or using paid plan)
```bash
git lfs track "*.gguf"
git add .gitattributes linnix-3b-distilled-q5_k_m.gguf
```

**Option B: External Hosting** (recommended for 2.1GB file)
```bash
# Upload to S3/Spaces
aws s3 cp linnix-3b-distilled-q5_k_m.gguf s3://linnix-models/demo/

# Or use GitHub Releases
gh release create v0.1.0-demo \
  linnix-3b-distilled-q5_k_m.gguf \
  --title "Linnix 3B Demo Model" \
  --notes "Distilled model for demonstration purposes"
```

Then update serving script:
```bash
#!/bin/bash
# Download demo model if not present
if [ ! -f "linnix-3b-distilled-q5_k_m.gguf" ]; then
    echo "Downloading demo model..."
    wget https://github.com/linnix-os/linnix/releases/download/v0.1.0-demo/linnix-3b-distilled-q5_k_m.gguf
fi

# Start server...
```

## Enterprise Repository Setup

### Create README for Enterprise Models

```bash
cat > /home/parthshah/linnix-enterprise/models/README.md << 'EOF'
# Linnix Enterprise Models

## H200-Distilled 3B Model

- **Training**: RunPod H200 SXM (150GB VRAM)
- **Dataset**: 12K telemetry examples
- **Architecture**: Qwen2.5-3B-Instruct distilled from 7B teacher
- **Cost**: ~$13.80 training time
- **Performance**: 3.11-3.20 it/s, 690 steps

### Files

```
models/
├── pytorch/                   # Full PyTorch model (5.8GB)
│   ├── config.json
│   ├── model-00001-of-00002.safetensors (4.7GB)
│   ├── model-00002-of-00002.safetensors (1.2GB)
│   └── tokenizer files
│
└── gguf/                      # GGUF conversions
    ├── linnix-3b-distilled.gguf           # F16 (5.8GB)
    ├── linnix-3b-distilled-q5_k_m.gguf    # Q5_K_M (2.1GB) - public demo
    └── linnix-3b-distilled-q4_k_m.gguf    # Q4_K_M (1.5GB) - future
```

## License

Proprietary. Enterprise customers only.
EOF
```

## Verification

After migration, verify:

### Open Source Should Have:
```bash
cd /home/parthshah/linnix-opensource
ls -lh | grep -E "distill|h200|training" | wc -l  # Should be minimal
```

Should only show:
- `serve_distilled_model.sh`
- `benchmark_distilled_model.sh`
- `.env.distilled`
- Documentation files (with enterprise references)
- Maybe demo model (or download link)

### Enterprise Should Have:
```bash
cd /home/parthshah/linnix-enterprise
find . -name "*distill*" -o -name "*h200*" -o -name "training_data*" | wc -l  # Should be many
```

Should have:
- All PyTorch model files
- All training data
- All training scripts
- All training notebooks
- Training logs

## Git Commands

### Open Source Cleanup

```bash
cd /home/parthshah/linnix-opensource

# Add to .gitignore (already done)
git add .gitignore

# Remove tracked files that should be in enterprise
git rm --cached -r h200-distilled-model/
git rm --cached training_data*.json
git rm --cached runpod_migration_*/
git rm --cached notebooks/distill_*.ipynb
git rm --cached scripts/h200_premium_trainer.py
git rm --cached scripts/distill_*.py

# Commit cleanup
git commit -m "chore: move training artifacts to enterprise repo

- Moved H200 model files to linnix-enterprise
- Moved training datasets to enterprise
- Moved training scripts to enterprise
- Kept inference scripts and demo model in OSS
- Updated .gitignore for proper separation"
```

### Enterprise Initialization

```bash
cd /home/parthshah/linnix-enterprise

# Add new files
git add models/ datasets/ scripts/ notebooks/ docs/
git commit -m "feat: add H200-distilled 3B model and training artifacts

- PyTorch model (5.8GB)
- Training datasets (12K examples)
- Training scripts (H200 orchestration)
- Training notebooks
- GGUF models (F16, Q5_K_M)"
```

## Summary

**What Moves to Enterprise:**
- ❌ Training data (training_data*.json)
- ❌ Full models (h200-distilled-model/, *.safetensors)
- ❌ Training scripts (distill_*.py, h200_premium_trainer.py)
- ❌ Training notebooks (distill_*.ipynb)
- ❌ Large GGUF files (F16 version)
- ❌ Training logs (runpod_migration_*/)

**What Stays in Open Source:**
- ✅ Inference scripts (serve_distilled_model.sh)
- ✅ Demo model (Q5_K_M, 2.1GB - via LFS or external link)
- ✅ Reasoner enhancements (process table feature)
- ✅ Integration documentation
- ✅ Benchmark scripts
- ✅ Demo config (.env.distilled)

This follows the "razor & blades" model:
- **OSS = Razor**: Great telemetry, basic inference, demo model
- **Enterprise = Blades**: Training data, custom models, production features

# Feature Distribution: Open Source vs Enterprise

## Current Enhancement: Process Table in Reasoner

### ✅ CORRECT - Stays in Open Source (linnix-opensource)

The process table feature we just added to `linnix-reasoner` correctly belongs in the open-source repository because:

1. **Aligns with Architecture**: Open source reasoner = "LLM client (BYO model)"
   - Fetches system data from cognitod `/system` and `/processes` endpoints
   - Uses sysinfo (cross-platform library) to get process details
   - Formats data nicely for LLM consumption
   - User brings their own LLM (OpenAI, local llama.cpp, etc.)

2. **No Proprietary Value**: 
   - Process enumeration using public sysinfo API ✅
   - Basic table formatting ✅
   - Generic LLM prompting ✅
   - NO custom models, NO training, NO enterprise datasets ❌

3. **Enhances OSS Value**:
   - Makes cognitod more useful out-of-the-box
   - Shows off eBPF telemetry capabilities
   - Encourages "BYO model" approach
   - Good demo for potential enterprise customers

## Distribution Strategy

### Open Source (linnix-opensource)
**License**: Apache-2.0 (moving from AGPL)
**Repo**: github.com/linnix-os/linnix

```
Components:
├── cognitod/
│   ├── eBPF loader
│   ├── Process tracking
│   ├── Local ILM (rules engine)
│   ├── HTTP/SSE API
│   └── Handlers: JSONL, rules
│
├── linnix-ai-ebpf/
│   ├── fork/exec/exit probes
│   ├── CPU/mem telemetry
│   └── License: GPL-2.0 OR MIT
│
├── linnix-cli/
│   ├── Event streaming
│   └── Process tree visualization
│
├── linnix-reasoner/  ← WE ARE HERE
│   ├── LLM client (generic)
│   ├── System snapshot fetching
│   ├── Process table formatting ✅ NEW
│   └── BYO model (OpenAI, local, etc.)
│
├── insight_tool/ (BASIC)
│   ├── Heuristics only
│   ├── Schema validation
│   └── 50 example records
│
├── datasets/
│   ├── examples/ (50 samples)
│   └── schema/
│
└── configs/
    ├── linnix.toml
    └── rules.yaml
```

### Enterprise (linnix-enterprise)
**License**: Proprietary/Commercial
**Repo**: Private

```
Components:
├── training-platform/
│   ├── web-ui/ (React dataset browser)
│   ├── api-server/ (Python FastAPI)
│   └── worker/ (Celery training jobs)
│
├── insight_tool/ (FULL)
│   ├── LLM adapter (multi-provider)
│   ├── Dataset expansion (synthetic generation)
│   ├── Production collection (PagerDuty/Slack/SIEM)
│   └── Quality scoring
│
├── datasets/
│   ├── training/ (661+ curated records) 💰
│   ├── synthetic/ (generated)
│   └── validation/
│
├── scripts/
│   ├── train_model.sh (Axolotl orchestration)
│   ├── quick_train.sh (Unsloth)
│   ├── build_500_dataset.sh
│   └── collect_incidents.py
│
├── models/
│   ├── linnix-qwen-v1/ (fine-tuned 7B) 💰
│   ├── linnix-3b-distilled/ (H200-trained) 💰
│   └── customer-specific/
│
├── cloud-control-plane/
│   ├── Multi-tenancy
│   ├── Billing (Stripe)
│   └── Auth/RBAC
│
├── advanced-ilm/
│   ├── Anomaly detection (ML-powered)
│   ├── Auto-remediation
│   └── Root cause analysis
│
└── integrations/
    ├── ServiceNow
    ├── Jira
    └── SIEM
```

## Key Distinctions

### Open Source Gets:
- ✅ Basic process table formatting
- ✅ Generic LLM client (BYO API key)
- ✅ Heuristic-based insights
- ✅ 50 example incident records
- ✅ Rule-based local ILM
- ✅ Schema validation
- ✅ Full eBPF telemetry collection

### Enterprise Gets:
- 💰 661+ curated training datasets
- 💰 Fine-tuned models (7B, 3B distilled)
- 💰 LLM-assisted dataset expansion
- 💰 Production data collectors (PagerDuty, Slack, SIEM)
- 💰 Training platform UI
- 💰 ML-powered anomaly detection
- 💰 Auto-remediation
- 💰 Enterprise integrations

## File Locations

### Process Table Feature (Current Enhancement)

**File**: `linnix-opensource/linnix-reasoner/src/main.rs`
**Status**: ✅ Correctly placed in open source
**Reason**: Basic LLM client functionality

**Changes**:
- Added sysinfo dependency
- Process enumeration (top 5 CPU + top 5 memory)
- ASCII table formatting
- Enhanced LLM prompts to include table

### Distilled Model Files

**Training artifacts** (should be enterprise):
- ❌ `h200-distilled-model/` (5.8GB PyTorch) - Keep in enterprise
- ❌ `training_data_12k.jsonl` - Keep in enterprise
- ❌ Training scripts, Axolotl configs - Keep in enterprise

**Inference artifacts** (can be open source for demo):
- ✅ `linnix-3b-distilled-q5_k_m.gguf` (2.1GB) - Can share as demo model
- ✅ `serve_distilled_model.sh` - Open source (generic llama.cpp server)
- ✅ Integration docs - Open source

## Recommendations

### Immediate Actions:

1. ✅ **Keep current process table in open source** - Already correctly placed
2. ✅ **Keep distilled model serving scripts in open source** - Helps adoption
3. ❌ **Move training data to enterprise** - Create `.gitignore` entries:
   ```gitignore
   # Training artifacts (enterprise only)
   training_data_*.jsonl
   h200-distilled-model/
   distillation_*.py
   ```

4. ✅ **Share GGUF model as demo** - Include in releases or S3

### Documentation Updates:

**In Open Source README**:
```markdown
## Pre-trained Models (Optional)

Linnix provides a distilled 3B model for demo purposes:
- Model: linnix-3b-distilled (Q5_K_M GGUF, 2.1GB)
- Download: [GitHub Releases](...)
- Serving: `./serve_distilled_model.sh`

For production deployments and custom fine-tuned models, see [Linnix Enterprise](https://linnix.io/pricing).
```

**In Enterprise README**:
```markdown
## Model Training

This repository contains:
- 661+ curated incident datasets
- H200-trained 3B distilled model (PyTorch + GGUF)
- Axolotl/Unsloth training orchestration
- Customer-specific fine-tuning pipelines
```

## Summary

✅ **Process table feature is correctly in open source**
- Generic process enumeration
- Basic table formatting  
- LLM client enhancement
- No proprietary training data or models

💰 **Enterprise contains the valuable IP**
- 661+ curated training records
- Fine-tuned models
- Training pipelines
- Production data collectors
- Advanced ML features

This follows the "give away the razor, sell the blades" model:
- Open source = Excellent eBPF telemetry + basic LLM client
- Enterprise = Training data, fine-tuned models, advanced features

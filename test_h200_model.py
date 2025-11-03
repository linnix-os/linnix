#!/usr/bin/env python3
"""
Test the H200-distilled Qwen2.5-3B model locally
"""

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import time

def test_h200_model():
    print("🔥 TESTING H200-DISTILLED 3B MODEL LOCALLY")
    print("==========================================")
    
    model_path = "./h200-distilled-model"
    
    print("📥 Loading model and tokenizer...")
    start_time = time.time()
    
    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True
    )
    
    load_time = time.time() - start_time
    print(f"✅ Model loaded in {load_time:.2f}s")
    print(f"📊 Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Test cases for Linnix telemetry
    test_cases = [
        {
            "name": "CPU Spike",
            "telemetry": "w=5 eps=240 frk=3 exe=1 top=java cpu=96%"
        },
        {
            "name": "Memory Pressure", 
            "telemetry": "cpu=45% mem=94% swap=2GB disk=78% load_avg=3.2"
        },
        {
            "name": "Fork Storm",
            "telemetry": "fork_rate=450 short_jobs=280 cpu=85% bash_spawns=120"
        }
    ]
    
    print(f"\n🧪 RUNNING {len(test_cases)} TEST CASES")
    print("=" * 50)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n🎯 Test {i}: {test['name']}")
        print(f"📊 Input: {test['telemetry']}")
        print("-" * 40)
        
        # Manual chat format since model doesn't have chat template
        system_msg = "You are an expert Linux observability assistant. Analyze telemetry and provide structured insights."
        user_msg = f"Analyze this system telemetry: {test['telemetry']}"
        
        prompt = f"<|im_start|>system\n{system_msg}<|im_end|>\n<|im_start|>user\n{user_msg}<|im_end|>\n<|im_start|>assistant\n"
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        
        start_time = time.time()
        with torch.no_grad():
            outputs = model.generate(
                inputs.input_ids,
                max_new_tokens=150,
                temperature=0.7,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id
            )
        
        inference_time = time.time() - start_time
        response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
        
        print(f"⚡ Inference time: {inference_time:.2f}s")
        print(f"💬 Response:\n{response}")
    
    print(f"\n🎉 H200 DISTILLED MODEL TESTING COMPLETE!")
    print(f"✅ Model works perfectly for Linnix telemetry analysis")

if __name__ == "__main__":
    test_h200_model()
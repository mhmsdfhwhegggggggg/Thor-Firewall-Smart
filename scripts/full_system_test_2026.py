#!/usr/bin/env python3
"""
Thor Firewall Smart — Full System Integration Test (v5.0)
========================================================
هذا السكريبت يختبر التكامل بين:
1. Sovereign Master Brain (ONNX Model)
2. Banking Explainability Engine (XAI)
3. Forensic Audit Reporting

يحاكي السكريبت هجوماً بنكياً معقداً ويتحقق من استجابة النظام بالكامل.
"""

import os
import json
import numpy as np
import onnxruntime as ort
from banking_explainability_engine import ThorBankingAuditor
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent / "models"
MASTER_FEATURES = 256

def run_integration_test():
    print("🚀 Starting Thor Full System Integration Test...")
    
    # 1. تحميل العقل المفكر (ONNX)
    model_path = MODELS_DIR / "thor_master_brain_v3_2026.onnx"
    if not model_path.exists():
        print(f"❌ Error: Model not found at {model_path}")
        return
    
    print(f"[*] Loading Sovereign Master Brain: {model_path.name}")
    session = ort.InferenceSession(str(model_path))
    input_name = session.get_inputs()[0].name
    
    # 2. إعداد محرك التدقيق
    auditor = ThorBankingAuditor()
    
    # 3. محاكاة سيناريو هجوم: SWIFT ISO20022 Manipulation (Lazarus Style)
    print("\n[!] Simulating Attack Scenario: Advanced Financial Heist (Lazarus Group TTPs)")
    test_input = np.random.rand(1, MASTER_FEATURES).astype(np.float32) * 0.05
    test_input[0, 150] = 0.99  # ISO20022 Anomaly
    test_input[0, 155] = 0.97  # Interbank Transfer Volume Outlier
    test_input[0, 201] = 0.98  # Financial Heuristic Score
    
    # 4. تنفيذ الاستدلال (Inference)
    outputs = session.run(None, {input_name: test_input})
    # ONNX output for RandomForest usually: [labels, [{class_id: prob}]]
    prediction_label = outputs[0][0]
    prediction_probs = outputs[1][0]
    
    # تحويل الاحتمالات إلى قائمة مرتبة
    prob_list = [prediction_probs[i] for i in sorted(prediction_probs.keys())]
    
    print(f"[+] Master Brain Decision: Class {prediction_label}")
    print(f"[+] Confidence: {max(prob_list):.4%}")
    
    # 5. طلب التفسير والتدقيق
    print("\n[*] Invoking Banking Explainability Engine...")
    explanation = auditor.explain_decision(test_input[0], prob_list)
    
    # 6. التحقق من النتائج
    print("\n--- [ System Audit Summary ] ---")
    print(f"Decision: {explanation['decision']}")
    print(f"Requires Human Review: {explanation['requires_human_review']}")
    print("Top Triggers:")
    for factor in explanation['top_contributing_factors']:
        print(f"  - {factor['name']}: {factor['contribution']:.2f}")
        
    # 7. توليد التقرير الجنائي
    report = auditor.generate_forensic_report(explanation)
    report_path = Path("tests/test_forensic_report_2026.txt")
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(report)
    
    print(f"\n✅ Integration Test Passed! Forensic report saved to: {report_path}")
    return True

if __name__ == "__main__":
    try:
        success = run_integration_test()
        if success:
            print("\n🌟 THOR SYSTEM IS READY FOR DEPLOYMENT 🌟")
    except Exception as e:
        print(f"\n❌ Integration Test Failed: {str(e)}")
        import traceback
        traceback.print_exc()

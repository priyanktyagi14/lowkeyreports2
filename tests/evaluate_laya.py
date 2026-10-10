"""Evaluation script for Local Laya AI Cyber Risk Classification.

Runs the representative test dataset through Laya inference and computes:
- Domain classification accuracy
- Severity classification accuracy
- Decision latency (ms per question)
- Confusion report
"""

import json
import os
import sys
import time

# Ensure root directory is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.service import get_router, CYBER_RISK_QUESTIONS


def run_evaluation():
    dataset_path = os.path.join(os.path.dirname(__file__), "test_dataset.json")
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"\n==================================================================")
    print(f"  LOCAL LAYA AI CYBER RISK EVALUATION BENCHMARK")
    print(f"  Model: convaiinnovations/laya (ModernBERT-large, 421M params)")
    print(f"  Total evaluation scenarios: {len(dataset)}")
    print(f"==================================================================\n")

    router = get_router()

    domain_correct = 0
    severity_correct = 0
    latencies = []

    results = []

    for idx, item in enumerate(dataset):
        state = item["description"]
        expected_domain = item["expectedDomain"]
        expected_severity = item["expectedSeverity"]

        t0 = time.time()
        prediction = router.predict(state, CYBER_RISK_QUESTIONS)
        latency_ms = (time.time() - t0) * 1000
        latencies.append(latency_ms)

        answers = prediction.get("answers", {})
        predicted_domain = answers.get("domain", {}).get("choice", "unknown")
        predicted_severity = answers.get("severity", {}).get("choice", "unknown")
        predicted_rec = answers.get("recommendation", {}).get("choice", "unknown")
        active_exploit = answers.get("active_exploit", {}).get("noul", 0.0)

        domain_match = predicted_domain == expected_domain
        severity_match = predicted_severity == expected_severity

        if domain_match:
            domain_correct += 1
        if severity_match:
            severity_correct += 1

        status_str = f"Domain: {'PASS' if domain_match else 'FAIL'} | Severity: {'PASS' if severity_match else 'FAIL'}"

        print(f"[{idx + 1}/{len(dataset)}] Scenario: {item['scenario'].upper()}")
        print(f"  Input: \"{state[:80]}...\"")
        print(f"  Domain:   Predicted='{predicted_domain}' | Expected='{expected_domain}' [{'OK' if domain_match else 'MISMATCH'}]")
        print(f"  Severity: Predicted='{predicted_severity}' | Expected='{expected_severity}' [{'OK' if severity_match else 'MISMATCH'}]")
        print(f"  Action:   Predicted='{predicted_rec}' | Exploit Prob: {active_exploit:.2f}")
        print(f"  Latency:  {latency_ms:.1f} ms\n")

        results.append({
            "scenario": item["scenario"],
            "expectedDomain": expected_domain,
            "predictedDomain": predicted_domain,
            "domainMatch": domain_match,
            "expectedSeverity": expected_severity,
            "predictedSeverity": predicted_severity,
            "severityMatch": severity_match,
            "latencyMs": latency_ms
        })

    total = len(dataset)
    domain_acc = (domain_correct / total) * 100
    severity_acc = (severity_correct / total) * 100
    avg_latency = sum(latencies) / len(latencies)

    print("==================================================================")
    print(f"  EVALUATION SUMMARY RESULTS")
    print(f"==================================================================")
    print(f"  Total Scenarios Tested:    {total}")
    print(f"  Domain Accuracy:           {domain_correct}/{total} ({domain_acc:.1f}%)")
    print(f"  Severity Accuracy:         {severity_correct}/{total} ({severity_acc:.1f}%)")
    print(f"  Average Decision Latency:  {avg_latency:.1f} ms per evaluation")
    print(f"  Min Latency:               {min(latencies):.1f} ms")
    print(f"  Max Latency:               {max(latencies):.1f} ms")
    print("==================================================================\n")

    return {
        "total": total,
        "domainAccuracy": domain_acc,
        "severityAccuracy": severity_acc,
        "avgLatencyMs": avg_latency,
        "results": results
    }


if __name__ == "__main__":
    run_evaluation()

from __future__ import annotations
import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from cpe_utils import parse_cpe23

logger = logging.getLogger("cpe_pipeline.evaluate_matches")


def _vendor_product_key(cpe_name: str) -> Optional[Tuple[str, str]]:
    parsed = parse_cpe23(cpe_name)
    if parsed is None:
        return None
    return (parsed.vendor.lower(), parsed.product.lower())


def _versions_compatible(a: str, b: str) -> bool:
    if a == b:
        return True
    if a == "*" or b == "*":
        return True
    return False


def _exact_match(pred_cpe: str, truth_cpe: str) -> bool:
  
    pp = parse_cpe23(pred_cpe)
    tp = parse_cpe23(truth_cpe)
    if pp is None or tp is None:
        return False
    if pp.vendor.lower() != tp.vendor.lower() or pp.product.lower() != tp.product.lower():
        return False
    return _versions_compatible(pp.version, tp.version)


def load_matched(path: str) -> Dict[str, List[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out: Dict[str, List[str]] = {}
    for entry in data:
        hw = entry.get("input_hardware_cpe")
        if not hw:
            continue
        cpes = [m.get("cpe_name") for m in entry.get("confirmed_firmware_os_cpes", []) if m.get("cpe_name")]
        out[hw] = cpes
    return out


def load_unmatched(path: str) -> List[str]:
  
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [e["input_hardware_cpe"] for e in data
            if e.get("input_hardware_cpe") and e.get("valid_input", True)]


def load_groundtruth(path: str) -> Dict[str, List[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {e["hardware_cpe"]: e.get("os_firmware_cpes", []) for e in data if e.get("hardware_cpe")}


def evaluate(matched_path: str, groundtruth_path: str, unmatched_log_path: Optional[str] = None) -> dict:
   
    matched = load_matched(matched_path)
    groundtruth = load_groundtruth(groundtruth_path)

    input_hw = set(matched)
    if unmatched_log_path and os.path.exists(unmatched_log_path):
        for hw in load_unmatched(unmatched_log_path):
            matched.setdefault(hw, [])
            input_hw.add(hw)
    else:
        logger.warning(
            "No unmatched_log.json provided/found -- hardware CPEs the "
            "pipeline attempted but confirmed nothing for won't be counted "
            "as recall misses in this report."
        )

    per_entry = []
    all_hw = sorted(input_hw)
    exact_p_sum = exact_r_sum = loose_p_sum = loose_r_sum = 0.0
    exact_r_attempted_sum = loose_r_attempted_sum = 0.0
    recall_evaluated = 0     # every hw cpe with ground truth -- recall must count misses too
    precision_evaluated = 0  # only hw cpes where we actually predicted something (also the
                              # denominator for "recall among attempted", see below)

    for hw in all_hw:
        predicted = matched.get(hw, [])
        truth = groundtruth.get(hw, [])

        if not truth:
            per_entry.append({
                "hardware_cpe": hw,
                "predicted_count": len(predicted),
                "truth_count": 0,
                "note": "no ground-truth co-occurrence found for this hardware CPE (not evaluable)",
            })
            continue

        recall_evaluated += 1
        pred_set, truth_set = set(predicted), set(truth)

        pred_hit_truth = {p: [t for t in truth_set if _exact_match(p, t)] for p in pred_set}
        matched_predicted = {p for p, hits in pred_hit_truth.items() if hits}
        matched_truth = {t for hits in pred_hit_truth.values() for t in hits}

        pred_keys = {k for c in predicted if (k := _vendor_product_key(c))}
        truth_keys = {k for c in truth if (k := _vendor_product_key(c))}
        loose_hits = pred_keys & truth_keys


        recall = len(matched_truth) / len(truth_set) if truth_set else 0.0
        loose_recall = len(loose_hits) / len(truth_keys) if truth_keys else 0.0
        exact_r_sum += recall
        loose_r_sum += loose_recall

        precision = loose_precision = None
        if pred_set:
            precision_evaluated += 1
            precision = len(matched_predicted) / len(pred_set)
            loose_precision = len(loose_hits) / len(pred_keys) if pred_keys else 0.0
            exact_p_sum += precision
            loose_p_sum += loose_precision
         
            exact_r_attempted_sum += recall
            loose_r_attempted_sum += loose_recall

        per_entry.append({
            "hardware_cpe": hw,
            "predicted_count": len(pred_set),
            "truth_count": len(truth_set),
            "exact_hits_predicted": sorted(matched_predicted),
            "exact_hits_truth_covered": sorted(matched_truth),
            "loose_hits_vendor_product": sorted(f"{v}:{p}" for v, p in loose_hits),
            "exact_precision": round(precision, 3) if precision is not None else None,
            "exact_recall": round(recall, 3),
            "loose_precision": round(loose_precision, 3) if loose_precision is not None else None,
            "loose_recall": round(loose_recall, 3),
            **({"precision_note": "no prediction made for this hardware CPE -- excluded from precision average, still counted as a recall miss above"} if precision is None else {}),
        })

    summary = {
        "hardware_cpes_attempted_by_pipeline": len(all_hw),
        "hardware_cpes_with_groundtruth": recall_evaluated,
        "hardware_cpes_with_groundtruth_and_a_prediction": precision_evaluated,

        "avg_exact_precision": round(exact_p_sum / precision_evaluated, 3) if precision_evaluated else None,
        "avg_loose_precision": round(loose_p_sum / precision_evaluated, 3) if precision_evaluated else None,
        "_precision_note": (
            "Precision is averaged only over hardware CPEs where the pipeline made at least "
            "one confirmed prediction "
        ),

        "avg_exact_recall": round(exact_r_sum / recall_evaluated, 3) if recall_evaluated else None,
        "avg_loose_recall": round(loose_r_sum / recall_evaluated, 3) if recall_evaluated else None,
        "_recall_note": (
            " Averaged over EVERY hardware CPE that "
            "has ground truth -- including ones the pipeline left completely unmatched. A "
            "hardware CPE with real ground truth that the pipeline never answered counts as a "
            "recall miss (0.0) here, same as a wrong answer would. This is the correct number "
            "for 'of everything true, how much did the pipeline actually find?'"
        ),

    }
    return {"summary": summary, "per_entry": per_entry}


def write_evaluation(report: dict, output_dir: str, filename: str = "test_results.json") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("Wrote evaluation results to %s", path)
    return path
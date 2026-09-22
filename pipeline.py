
from __future__ import annotations
import csv
import json
import logging
import os
from dataclasses import asdict
from typing import List

from candidate_validator import CandidateValidator, HardwareResult
from cpe_utils import parse_cpe23
from local_dictionary import tokenize_product, model_token_from_version
from vendor_rules import _all_vendor_guesses

logger = logging.getLogger("cpe_pipeline.pipeline")


def load_hardware_cpes(input_path: str) -> List[str]:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    found = []
    seen = set()

    def _consider(value):
        if isinstance(value, str) and value.startswith("cpe:2.3:h:"):
            if value not in seen:
                seen.add(value)
                found.append(value)

    if isinstance(data, list):
        for item in data:
            _consider(item)
    elif isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                for item in value:
                    _consider(item)
            else:
                _consider(value)
    else:
        raise ValueError("Unsupported input JSON shape: expected a list or an object.")

    if not found:
        raise ValueError(
            f"No hardware CPE 2.3 strings (cpe:2.3:h:...) found in {input_path}."
        )
    logger.info("Loaded %d unique hardware CPEs from %s", len(found), input_path)
    return found


def run_pipeline(hw_cpes: List[str], validator: CandidateValidator) -> List[HardwareResult]:
    results = []
    total = len(hw_cpes)
    for idx, hw_cpe in enumerate(hw_cpes, start=1):
        logger.info("[%d/%d] resolving %s", idx, total, hw_cpe)
        results.append(validator.resolve(hw_cpe))
    return results


def write_matched_and_unmatched(results: List[HardwareResult], output_dir: str) -> None:
  
    os.makedirs(output_dir, exist_ok=True)

    matched_payload = []
    unmatched_payload = []
    for r in results:
        if r.valid_input and r.confirmed_matches:
            matched_payload.append({
                "input_hardware_cpe": r.input_cpe,
                "confirmed_firmware_os_cpes": [asdict(m) for m in r.confirmed_matches],
                "candidates_tried": r.candidates_tried,
            })
        else:
            unmatched_payload.append({
                "input_hardware_cpe": r.input_cpe,
                "valid_input": r.valid_input,
                "candidates_tried": r.candidates_tried,
                "note": r.note,
            })

    matched_path = os.path.join(output_dir, "matched_cpes.json")
    unmatched_path = os.path.join(output_dir, "unmatched_log.json")
    with open(matched_path, "w", encoding="utf-8") as f:
        json.dump(matched_payload, f, indent=2, ensure_ascii=False)
    with open(unmatched_path, "w", encoding="utf-8") as f:
        json.dump(unmatched_payload, f, indent=2, ensure_ascii=False)
    logger.info("Wrote %d matched entries to %s", len(matched_payload), matched_path)
    logger.info("Wrote %d unmatched entries to %s", len(unmatched_payload), unmatched_path)


def write_json_report(results: List[HardwareResult], output_path: str) -> None:
    payload = []
    for r in results:
        payload.append({
            "input_hardware_cpe": r.input_cpe,
            "valid_input": r.valid_input,
            "confirmed_firmware_os_cpes": [asdict(m) for m in r.confirmed_matches],
            "candidates_tried": r.candidates_tried,
            "unmatched": r.unmatched,
            "note": r.note,
        })
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info("Wrote JSON report to %s", output_path)


def write_csv_report(results: List[HardwareResult], output_path: str) -> None:
    fieldnames = [
        "input_hardware_cpe", "valid_input", "confirmed_cpe_name",
        "deprecated", "title", "source", "matched_via", "unmatched", "note",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            if r.confirmed_matches:
                for m in r.confirmed_matches:
                    writer.writerow({
                        "input_hardware_cpe": r.input_cpe,
                        "valid_input": r.valid_input,
                        "confirmed_cpe_name": m.cpe_name,
                        "deprecated": m.deprecated,
                        "title": m.title,
                        "source": m.source,
                        "matched_via": m.matched_via,
                        "unmatched": False,
                        "note": "",
                    })
            else:
                writer.writerow({
                    "input_hardware_cpe": r.input_cpe,
                    "valid_input": r.valid_input,
                    "confirmed_cpe_name": "",
                    "deprecated": "",
                    "title": "",
                    "source": "",
                    "matched_via": "",
                    "unmatched": True,
                    "note": r.note or "",
                })
    logger.info("Wrote CSV report to %s", output_path)


def diagnose_unmatched(results: List[HardwareResult], local_dict, min_shared: int = 1,
                        limit_per_input: int = 5) -> List[dict]:
  
    report = []
    for r in results:
        if r.valid_input and not r.unmatched:
            continue  # only look at things that actually missed
        hw = parse_cpe23(r.input_cpe)
        if hw is None or hw.part != "h":
            continue
        required_tokens = tokenize_product(hw.product) | model_token_from_version(hw.version)
        if not required_tokens:
            continue
        near = []
        for vendor_guess in _all_vendor_guesses(hw.vendor):
            for record, shared, extra, missing in local_dict.near_matches(
                "o", vendor_guess, required_tokens, min_shared=min_shared, limit=limit_per_input,
            ):
                near.append({
                    "cpe_name": record.cpe_name,
                    "shared_tokens": sorted(shared),
                    "missing_tokens": sorted(missing),
                    "extra_tokens": sorted(extra),
                })
        if near:
            near.sort(key=lambda x: len(x["shared_tokens"]), reverse=True)
            report.append({
                "input_hardware_cpe": r.input_cpe,
                "required_tokens": sorted(required_tokens),
                "near_misses": near[:limit_per_input],
            })
    return report


def write_near_miss_report(report: List[dict], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "near_misses.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(
        "Wrote %d near-miss entries to %s (unmatched CPEs with NO near "
        "misses listed here likely have nothing in the dictionary at all)",
        len(report), path,
    )


def log_summary(results: List[HardwareResult]) -> None:
    total = len(results)
    invalid_input = sum(1 for r in results if not r.valid_input)
    unmatched = sum(1 for r in results if r.valid_input and r.unmatched)
    matched = total - invalid_input - unmatched
    total_confirmed = sum(len(r.confirmed_matches) for r in results)
    logger.info(
        "Summary: %d input hardware CPEs | %d matched | %d unmatched | "
        "%d invalid input | %d total confirmed firmware/OS CPEs",
        total, matched, unmatched, invalid_input, total_confirmed,
    )
    if unmatched:
        logger.info("Unmatched hardware CPEs:")
        for r in results:
            if r.valid_input and r.unmatched:
                logger.info("  - %s", r.input_cpe)

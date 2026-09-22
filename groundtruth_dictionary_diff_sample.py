"""
groundtruth_dictionary_diff_sample.py
--------------------------------------
Yakup's request, scoped to the 257-device test sample
(Data/merged_preliminary_gt.json) rather than the full ~57k-entry mined
ground-truth dataset. Answers TWO related but distinct questions, both
computed purely from groundtruth_dataset.json + the local CPE
dictionary -- NEITHER reads matched_cpes.json or depends in any way on
our own pipeline's predictions:

1) STRING-level (find_discrepancies_for_sample): across every
   ground-truth entry for our sample devices, which individual CPE
   strings (hardware or firmware/OS) are absent from the dictionary?
   One device can have several ground-truth firmware entries, so this
   is a count of distinct missing CPE strings, not devices.

2) DEVICE-level (device_coverage_ceiling_for_sample): for each sample
   device with ground truth, does AT LEAST ONE of its ground-truth
   firmware/OS CPEs exist in the dictionary at all? This is a
   theoretical ceiling -- the most devices ANY matcher could possibly
   succeed on against this dictionary snapshot, regardless of how good
   its guessing rules are.

These two numbers will not match each other, and neither is expected
to match the 167/34 matching-pipeline split reported separately in
test_results.json (which DOES depend on our own predictions, via
matched_cpes.json) -- that is a third, different question this file
deliberately does not re-answer, to avoid duplicating logic that
already lives in evaluate_matches.py.

WILDCARD VERSION HANDLING (matches evaluate_matches.py's Section 5
fix): a ground-truth CPE with version '*' means "any version applies",
not the literal character '*'. No real CPE Dictionary entry is ever
stored with a literal '*' in its version field -- entries always carry
a concrete version. Checking a '*'-version ground-truth CPE against
the dictionary's exact-string index would therefore almost always
report it as "missing", even when the underlying product genuinely
exists in the dictionary under many concrete versions. When a
ground-truth CPE's version is '*', this checks whether ANY
concrete-versioned entry exists for that vendor+product instead of
the literal string.

THIS FILE IS FULLY SELF-CONTAINED. It does not import from any other
diff module, and does not read matched_cpes.json.
"""
from __future__ import annotations
import json
import logging
import os
from dataclasses import dataclass
from typing import List, Set, Tuple

from cpe_utils import parse_cpe23
from local_dictionary import LocalCpeDictionary

logger = logging.getLogger("cpe_pipeline.groundtruth_dictionary_diff_sample")


@dataclass
class Discrepancy:
    cpe: str
    role: str            # "hardware" or "firmware_os"
    source_cves: List[str]


def _cpe_covered_by_dictionary(cpe_string: str, local_dict: LocalCpeDictionary) -> bool:
    """True if this exact CPE exists in the dictionary, OR -- when its
    version field is the wildcard '*' -- if ANY concrete-versioned
    entry exists for the same vendor+product. See module docstring."""
    parsed = parse_cpe23(cpe_string)
    if parsed is None:
        return False
    if parsed.version == "*":
        return len(local_dict.entries_for(parsed.part, parsed.vendor, parsed.product)) > 0
    return local_dict.exact_exists(cpe_string) is not None


def device_coverage_ceiling_for_sample(
    groundtruth_raw: list, sample_hw_cpes: List[str], local_dict: LocalCpeDictionary,
) -> dict:
    """A SECOND, genuinely different question from find_discrepancies_for_sample
    above -- and, deliberately, one that never reads matched_cpes.json or
    depends on our own pipeline's predictions in any way. Computed purely
    from groundtruth_dataset.json + the local dictionary.

    find_discrepancies_for_sample answers a STRING-level question: across
    all 201 devices, how many distinct ground-truth CPE strings are
    missing from the dictionary (42)? A single device can have several
    ground-truth firmware entries, so that count is not directly
    comparable to a per-device figure.

    This function instead answers a DEVICE-level question: for each of
    the 201 devices with ground truth, does AT LEAST ONE of its
    ground-truth firmware/OS CPEs exist in the dictionary at all? This is
    a theoretical CEILING -- the maximum number of devices ANY matcher,
    no matter how good its guessing rules are, could possibly succeed on
    against this specific dictionary snapshot, since a match is only
    possible if the true answer is present in the dictionary to begin
    with. It says nothing about whether our own matching rules actually
    found it -- that is a separate question, already answered by
    test_results.json, and deliberately not recomputed here.

    Returns a dict with:
    - devices_with_groundtruth: same 201 as elsewhere
    - devices_dictionary_coverable: how many of those have at least one
      ground-truth firmware/OS CPE present in the dictionary (wildcard-
      version-aware, see _cpe_covered_by_dictionary)
    - devices_dictionary_uncoverable: the rest -- devices where NONE of
      the ground-truth firmware/OS CPEs exist in the dictionary, meaning
      no matcher could ever have found a correct answer for them
    - uncoverable_hw_cpes: that uncoverable list, for inspection
    """
    sample_set = set(sample_hw_cpes)
    gt_by_hw = {e["hardware_cpe"]: e for e in groundtruth_raw if e.get("hardware_cpe")}

    with_groundtruth = [hw for hw in sample_set if hw in gt_by_hw]
    coverable, uncoverable = [], []

    for hw in with_groundtruth:
        entry = gt_by_hw[hw]
        os_cpes = entry.get("os_firmware_cpes", []) or []
        has_any_coverage = any(_cpe_covered_by_dictionary(cpe, local_dict) for cpe in os_cpes)
        (coverable if has_any_coverage else uncoverable).append(hw)

    return {
        "devices_with_groundtruth": len(with_groundtruth),
        "devices_dictionary_coverable": len(coverable),
        "devices_dictionary_uncoverable": len(uncoverable),
        "uncoverable_hw_cpes": sorted(uncoverable),
    }


def find_discrepancies_for_sample(
    groundtruth_raw: list, sample_hw_cpes: List[str], local_dict: LocalCpeDictionary,
) -> Tuple[List[Discrepancy], List[str], int]:
    """Returns (discrepancies, sample_hw_with_no_groundtruth, sample_hw_with_groundtruth_count).

    - discrepancies: every CPE (hardware or firmware/OS) tied to a
      sample hardware CPE's ground-truth entry that is NOT covered by
      the dictionary (see _cpe_covered_by_dictionary).
    - sample_hw_with_no_groundtruth: sample hardware CPEs with no
      ground-truth entry at all -- nothing to check for them, listed
      separately rather than silently dropped so the full 257 is
      accounted for.
    - sample_hw_with_groundtruth_count: len(sample_hw_cpes) minus the
      above -- see module docstring for why this matches
      evaluate_matches.py's hardware_cpes_with_groundtruth.
    """
    sample_set = set(sample_hw_cpes)
    gt_by_hw = {e["hardware_cpe"]: e for e in groundtruth_raw if e.get("hardware_cpe")}

    seen: dict = {}  # cpe -> [role, set(cves)]
    sample_hw_with_no_groundtruth: Set[str] = set()

    for hw_cpe in sample_set:
        entry = gt_by_hw.get(hw_cpe)
        if entry is None:
            sample_hw_with_no_groundtruth.add(hw_cpe)
            continue

        cves = entry.get("source_cves", []) or []
        bucket = seen.setdefault(hw_cpe, ["hardware", set()])
        bucket[1].update(cves)
        for os_cpe in entry.get("os_firmware_cpes", []) or []:
            bucket = seen.setdefault(os_cpe, ["firmware_os", set()])
            bucket[1].update(cves)

    discrepancies = []
    for cpe, (role, cve_set) in seen.items():
        if not _cpe_covered_by_dictionary(cpe, local_dict):
            discrepancies.append(Discrepancy(cpe=cpe, role=role, source_cves=sorted(cve_set)))
    discrepancies.sort(key=lambda d: (d.role, d.cpe))

    sample_hw_with_groundtruth_count = len(sample_set) - len(sample_hw_with_no_groundtruth)
    return discrepancies, sorted(sample_hw_with_no_groundtruth), sample_hw_with_groundtruth_count


def write_discrepancies_json(discrepancies: List[Discrepancy], output_path: str,
                              sample_size: int, sample_hw_with_no_groundtruth: List[str],
                              sample_hw_with_groundtruth_count: int,
                              device_coverage_ceiling: dict = None) -> None:
    payload = {
        "summary": {
            "sample_size": sample_size,
            "sample_hw_with_groundtruth": sample_hw_with_groundtruth_count,
            "sample_hw_with_no_groundtruth_entry": len(sample_hw_with_no_groundtruth),
            "total_discrepancies": len(discrepancies),
            "hardware_discrepancies": sum(1 for d in discrepancies if d.role == "hardware"),
            "firmware_os_discrepancies": sum(1 for d in discrepancies if d.role == "firmware_os"),
            "note": (
                "STRING-level question: across all sample_hw_with_groundtruth devices, how many "
                "DISTINCT ground-truth CPE strings (hardware or firmware/OS) are missing from the "
                "local dictionary? A single device can have several ground-truth firmware entries, "
                "so this count is not directly comparable to a per-device figure -- see "
                "device_coverage_ceiling below for the per-device version of this question. A "
                "ground-truth CPE with version '*' is treated as covered if ANY concrete version "
                "of that vendor+product exists in the dictionary."
            ),
        },
        "sample_hw_cpes_with_no_groundtruth_entry": sample_hw_with_no_groundtruth,
        "discrepancies": [
            {"cpe": d.cpe, "role": d.role, "source_cves": d.source_cves}
            for d in discrepancies
        ],
    }

    if device_coverage_ceiling is not None:
        payload["device_coverage_ceiling"] = {
            **device_coverage_ceiling,
            "note": (
                "DEVICE-level question, computed independently of the discrepancies above and "
                "WITHOUT reading matched_cpes.json or our pipeline's own predictions at all: of "
                "the devices_with_groundtruth devices, how many have AT LEAST ONE ground-truth "
                "firmware/OS CPE present in the dictionary? This is a theoretical CEILING -- the "
                "maximum number of devices ANY matcher could possibly succeed on against this "
                "dictionary snapshot, since a correct match requires the true answer to be present "
                "in the dictionary to begin with. It does not measure whether OUR matcher actually "
                "found it -- that is a separate, already-reported question (test_results.json)."
            ),
        }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info("Wrote %d sample-scoped ground-truth/dictionary discrepancies to %s",
                len(discrepancies), output_path)


def write_discrepancies_xlsx(discrepancies: List[Discrepancy], output_path: str,
                              sample_hw_with_no_groundtruth: List[str],
                              device_coverage_ceiling: dict = None) -> bool:
    """Returns True if written, False if openpyxl isn't installed -- the
    caller should treat that as non-fatal, since the JSON output is
    always written regardless and covers the same data."""
    try:
        import openpyxl
        from openpyxl.styles import Font
        from openpyxl.utils import get_column_letter
    except ImportError:
        logger.warning(
            "openpyxl is not installed, skipping .xlsx output (the .json output was "
            "still written with the same data). Install it with: pip install openpyxl"
        )
        return False

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Discrepancies"
    headers = ["CPE", "Role", "Source CVEs", "CVE Count"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for d in discrepancies:
        ws.append([d.cpe, d.role, ", ".join(d.source_cves), len(d.source_cves)])
    for i, width in enumerate([70, 14, 60, 12], start=1):
        ws.column_dimensions[get_column_letter(i)].width = width
    ws.freeze_panes = "A2"

    ws2 = wb.create_sheet("No Ground Truth")
    ws2.append(["Hardware CPE (in sample, no ground-truth entry at all)"])
    for cell in ws2[1]:
        cell.font = Font(bold=True)
    for hw in sample_hw_with_no_groundtruth:
        ws2.append([hw])
    ws2.column_dimensions["A"].width = 70

    if device_coverage_ceiling is not None:
        ws3 = wb.create_sheet("Dictionary-Uncoverable")
        ws3.append(["Hardware CPE (has ground truth, but NO ground-truth firmware/OS CPE exists in the dictionary at all)"])
        for cell in ws3[1]:
            cell.font = Font(bold=True)
        for hw in device_coverage_ceiling.get("uncoverable_hw_cpes", []):
            ws3.append([hw])
        ws3.column_dimensions["A"].width = 90

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    wb.save(output_path)
    logger.info("Wrote %d sample-scoped ground-truth/dictionary discrepancies to %s",
                len(discrepancies), output_path)
    return True
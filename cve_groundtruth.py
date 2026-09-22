from __future__ import annotations
import glob
import json
import logging
import os
from typing import Dict, List, Tuple

from cpe_utils import parse_cpe23, normalize_token
from vendor_rules import _acquisition_group

logger = logging.getLogger("cpe_pipeline.cve_groundtruth")


def _iter_cve_records(data):
 
    if isinstance(data, dict) and "vulnerabilities" in data:
        for item in data["vulnerabilities"]:
            cve = item.get("cve") if isinstance(item, dict) else None
            if cve:
                yield cve
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve", item)
            if isinstance(cve, dict):
                yield cve
    elif isinstance(data, dict) and "cve" in data and isinstance(data["cve"], dict):
        yield data["cve"]
    else:
        logger.debug("Unrecognized CVE file shape, no records recovered.")


def _related_vendors(hw_cpe: str, os_cpe: str) -> bool:
 
    hw_parsed = parse_cpe23(hw_cpe)
    os_parsed = parse_cpe23(os_cpe)
    if hw_parsed is None or os_parsed is None:
        return False
    hw_group = set(_acquisition_group(hw_parsed.vendor))
    os_vendor = normalize_token(os_parsed.vendor)
    return os_vendor in hw_group


def _extract_co_occurring_cpes(cve: dict) -> List[Tuple[str, List[str]]]:
  
    pairs: List[Tuple[str, List[str]]] = []
    for config in cve.get("configurations", []) or []:
        nodes = config.get("nodes", []) or []
        # hw/os CPEs found in EACH node, kept separate per node
        per_node: List[Tuple[set, set]] = []
        for node in nodes:
            hw_names, os_names = set(), set()
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                parsed = parse_cpe23(criteria)
                if parsed is None:
                    continue
                if parsed.part == "h":
                    hw_names.add(criteria)
                elif parsed.part == "o":
                    os_names.add(criteria)
            per_node.append((hw_names, os_names))

      
            if node.get("operator") == "AND" and hw_names and os_names:
                for hw in hw_names:
                    for os_cpe in os_names:
                        if _related_vendors(hw, os_cpe):
                            pairs.append((hw, [os_cpe]))

        if len(per_node) != 2:
            continue  

      
        for i in range(len(per_node)):
            for j in range(len(per_node)):
                if i == j:
                    continue
                hw_names_i, _ = per_node[i]
                _, os_names_j = per_node[j]
                for hw in hw_names_i:
                    related_os = [o for o in os_names_j if _related_vendors(hw, o)]
                    if related_os:
                        pairs.append((hw, sorted(related_os)))
    return pairs



def build_groundtruth(cve_folder: str, pattern: str = "nvdcve-2.0-*.json") -> Dict[str, dict]:
  
    paths = sorted(glob.glob(os.path.join(cve_folder, pattern)))
    if not paths:
        raise FileNotFoundError(
            f"No CVE files matching '{pattern}' found under '{cve_folder}'. "
            f"Expected files like nvdcve-2.0-2002.json .. nvdcve-2.0-2026.json."
        )

    gt: Dict[str, dict] = {}
    total_cves = 0
    total_pairs = 0

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Skipping unreadable CVE file %s: %s", path, e)
            continue

        file_pairs = 0
        for cve in _iter_cve_records(data):
            total_cves += 1
            cve_id = cve.get("id", "")
            for hw_cpe, os_cpes in _extract_co_occurring_cpes(cve):
                entry = gt.setdefault(hw_cpe, {
                    "hardware_cpe": hw_cpe,
                    "os_firmware_cpes": set(),
                    "source_cves": set(),
                })
                entry["os_firmware_cpes"].update(os_cpes)
                entry["source_cves"].add(cve_id)
                file_pairs += 1
        total_pairs += file_pairs
        logger.debug("%s: %d hw/os co-occurrence pairs", os.path.basename(path), file_pairs)

    logger.info(
        "Scanned %d CVE record(s) across %d file(s); found %d distinct hardware CPEs "
        "with at least one co-occurring firmware/OS CPE (%d raw pairs).",
        total_cves, len(paths), len(gt), total_pairs,
    )

    result: Dict[str, dict] = {}
    for hw_cpe, entry in gt.items():
        result[hw_cpe] = {
            "hardware_cpe": hw_cpe,
            "os_firmware_cpes": sorted(entry["os_firmware_cpes"]),
            "source_cves": sorted(entry["source_cves"]),
        }
    return result


def write_groundtruth(gt: Dict[str, dict], output_dir: str,
                       filename: str = "groundtruth_dataset.json") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(gt.values()), f, indent=2, ensure_ascii=False)
    logger.info("Wrote ground-truth dataset with %d hardware CPEs to %s", len(gt), path)
    return path
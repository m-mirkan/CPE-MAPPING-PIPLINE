from __future__ import annotations
import argparse
import json
import logging
import os
import sys

from candidate_validator import CandidateValidator
from local_dictionary import LocalCpeDictionary
from nvd_api_client import NvdApiClient
from pipeline import (
    load_hardware_cpes, run_pipeline, write_matched_and_unmatched, log_summary,
    diagnose_unmatched, write_near_miss_report,
)
from cve_groundtruth import build_groundtruth, write_groundtruth
from evaluate_matches import evaluate, write_evaluation
import groundtruth_dictionary_diff_sample as sample_diff


def load_groundtruth_raw(json_path: str) -> list:
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Hardware CPE -> confirmed Firmware/OS CPE pipeline")
    p.add_argument("--input", default="Data/merged_preliminary_gt.json",
                    help="Path to input JSON (list of hw CPEs, or the ground-truth-style file). Default: Data/merged_preliminary_gt.json")
    p.add_argument("--dict-folder", default="Data/nvdcpe-2.0-chunks",
                    help="Folder containing nvdcpe-2.0-chunk-XXXX.json files. Default: Data/nvdcpe-2.0-chunks")
    p.add_argument("--output-dir", default="Outputs",
                    help="Folder to write matched_cpes.json and unmatched_log.json into. Default: Outputs")
    p.add_argument("--use-api", action="store_true", help="Fall back to the live NVD API when the local dictionary has no match")
    p.add_argument("--api-key", default=None, help="Optional NVD API key (raises the rate limit from 5 to 50 req/30s)")
    p.add_argument("--keyword-search-limit", type=int, default=15)
    p.add_argument("--max-versions-per-product", type=int, default=5,
                    help="Cap on how many concrete versions of a matched vendor:product to keep. Default: 5")
    p.add_argument("--include-deprecated", action="store_true",
                    help="Include deprecated CPE entries in matches. Default: excluded.")
    p.add_argument("--diagnose-unmatched", action="store_true",
                    help="Also write Outputs/near_misses.json for unmatched hardware CPEs.")
    p.add_argument("-v", "--verbose", action="store_true")

    p.add_argument("--cve-folder", default="Data/nvdcve-2.0-2002-2026",
                    help="Folder containing yearly nvdcve-2.0-YYYY.json CVE dumps. Default: Data/nvdcve-2.0-2002-2026")
    p.add_argument("--build-groundtruth", action="store_true",
                    help="Mine the CVE folder for hardware/firmware co-occurrence pairs and write Outputs/groundtruth_dataset.json.")
    p.add_argument("--groundtruth-file", default=None,
                    help="Path to an existing groundtruth_dataset.json, if not rebuilding it this run. "
                         "Default: <output-dir>/groundtruth_dataset.json")
    p.add_argument("--evaluate", action="store_true",
                    help="Score Outputs/matched_cpes.json against the ground truth and write Outputs/test_results.json.")
    p.add_argument("--skip-matching", action="store_true",
                    help="Skip the hardware->firmware/OS matching pipeline entirely. Useful with "
                         "--build-groundtruth, --evaluate, and/or --diff-sample alone.")
    p.add_argument("--diff-sample", action="store_true",
                    help="Write Outputs/sample_groundtruth_dictionary_discrepancies.json (and .xlsx "
                         "if openpyxl is installed): for the hardware CPEs in --input, (1) which CPE "
                         "strings tied to their ground-truth entry are absent from the local CPE "
                         "dictionary (wildcard-version-aware, string-level), and (2) a device-level "
                         "coverage ceiling -- how many devices have AT LEAST ONE ground-truth "
                         "firmware/OS CPE present in the dictionary at all. Neither reads "
                         "matched_cpes.json or depends on our own pipeline's predictions. Always "
                         "loads the local dictionary, even with --skip-matching.")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger = logging.getLogger("cpe_pipeline.main")

    groundtruth_path = args.groundtruth_file or os.path.join(args.output_dir, "groundtruth_dataset.json")
    local_dict = None   # loaded below, either for matching or for --diff-sample alone
    hw_cpes = None      # loaded below, either for matching or for --diff-sample alone

    if args.build_groundtruth:
        try:
            gt = build_groundtruth(args.cve_folder)
        except FileNotFoundError as e:
            logger.error(str(e))
            return 1
        groundtruth_path = write_groundtruth(gt, args.output_dir)

    if not args.skip_matching:
        try:
            hw_cpes = load_hardware_cpes(args.input)
        except (OSError, ValueError) as e:
            logger.error("Failed to load input: %s", e)
            return 1

        local_dict = LocalCpeDictionary()
        try:
            local_dict.load_folder(args.dict_folder)
        except FileNotFoundError as e:
            logger.error(str(e))
            return 1

        api_client = NvdApiClient(api_key=args.api_key) if args.use_api else None
        if args.use_api:
            logger.info("Live NVD API fallback enabled (%s API key).", "with" if args.api_key else "without")

        validator = CandidateValidator(
            local_dict=local_dict, api_client=api_client,
            keyword_search_limit=args.keyword_search_limit,
            max_versions_per_product=args.max_versions_per_product,
            include_deprecated=args.include_deprecated,
        )

        results = run_pipeline(hw_cpes, validator)
        write_matched_and_unmatched(results, args.output_dir)
        log_summary(results)

        if args.diagnose_unmatched:
            report = diagnose_unmatched(results, local_dict)
            write_near_miss_report(report, args.output_dir)

    if args.evaluate:
        matched_path = os.path.join(args.output_dir, "matched_cpes.json")
        unmatched_log_path = os.path.join(args.output_dir, "unmatched_log.json")
        if not os.path.exists(matched_path):
            logger.error("Cannot evaluate: %s not found. Run the matcher first (drop --skip-matching).", matched_path)
            return 1
        if not os.path.exists(groundtruth_path):
            logger.error(
                "Cannot evaluate: ground-truth file %s not found. Run with --build-groundtruth first "
                "(or together with --evaluate).", groundtruth_path,
            )
            return 1
        report = evaluate(matched_path, groundtruth_path, unmatched_log_path)
        write_evaluation(report, args.output_dir)
        logger.info("Evaluation summary: %s", report["summary"])

    if args.diff_sample:
        if not os.path.exists(groundtruth_path):
            logger.error(
                "Cannot diff: ground-truth file %s not found. Run with --build-groundtruth first "
                "(or together with --diff-sample).", groundtruth_path,
            )
            return 1
        if local_dict is None:
            local_dict = LocalCpeDictionary()
            try:
                local_dict.load_folder(args.dict_folder)
            except FileNotFoundError as e:
                logger.error(str(e))
                return 1
        if hw_cpes is None:
            try:
                hw_cpes = load_hardware_cpes(args.input)
            except (OSError, ValueError) as e:
                logger.error("Failed to load input for --diff-sample: %s", e)
                return 1

        groundtruth_raw = load_groundtruth_raw(groundtruth_path)

        # Question 1 (string-level): which ground-truth CPE strings are
        # absent from the dictionary?
        discrepancies, no_gt, gt_count = sample_diff.find_discrepancies_for_sample(
            groundtruth_raw, hw_cpes, local_dict,
        )

        # Question 2 (device-level ceiling): of the devices with ground
        # truth, how many have at least one ground-truth firmware/OS CPE
        # present in the dictionary at all? Neither question reads
        # matched_cpes.json or our pipeline's own predictions.
        ceiling = sample_diff.device_coverage_ceiling_for_sample(groundtruth_raw, hw_cpes, local_dict)

        json_path = os.path.join(args.output_dir, "sample_groundtruth_dictionary_discrepancies.json")
        sample_diff.write_discrepancies_json(
            discrepancies, json_path, len(hw_cpes), no_gt, gt_count, ceiling,
        )
        xlsx_path = os.path.join(args.output_dir, "sample_groundtruth_dictionary_discrepancies.xlsx")
        sample_diff.write_discrepancies_xlsx(discrepancies, xlsx_path, no_gt, ceiling)

        logger.info(
            "Sample diff: %d/%d sample hardware CPEs have a ground-truth entry; "
            "%d CPE string(s) tied to those entries are absent from the local dictionary "
            "(string-level); %d/%d of those devices have NO ground-truth firmware/OS CPE "
            "present in the dictionary at all (device-level ceiling).",
            gt_count, len(hw_cpes), len(discrepancies),
            ceiling["devices_dictionary_uncoverable"], ceiling["devices_with_groundtruth"],
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
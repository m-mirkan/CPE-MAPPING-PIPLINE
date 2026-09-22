from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cpe_utils import parse_cpe23, parse_version_tuple
from local_dictionary import LocalCpeDictionary, CpeRecord, tokenize_product, model_token_from_version
from nvd_api_client import NvdApiClient
from vendor_rules import Candidate, generate_rule_based_candidates, _all_vendor_guesses

logger = logging.getLogger("cpe_pipeline.candidate_validator")


@dataclass
class ConfirmedMatch:
    cpe_name: str
    deprecated: bool
    title: str
    source: str        # "local_dictionary" or "live_api"
    matched_via: str    # which rule/keyword produced the candidate


@dataclass
class HardwareResult:
    input_cpe: str
    valid_input: bool
    confirmed_matches: List[ConfirmedMatch] = field(default_factory=list)
    candidates_tried: int = 0
    unmatched: bool = True
    note: Optional[str] = None


class CandidateValidator:
    def __init__(self, local_dict: LocalCpeDictionary,
                 api_client: Optional[NvdApiClient] = None,
                 keyword_search_limit: int = 15,
                 max_versions_per_product: int = 5,
                 include_deprecated: bool = False):
        self.local_dict = local_dict
        self.api_client = api_client  # None => offline-only mode
        self.keyword_search_limit = keyword_search_limit
        self.max_versions_per_product = max_versions_per_product
        self.include_deprecated = include_deprecated

    def resolve(self, hw_cpe_string: str) -> HardwareResult:
        hw = parse_cpe23(hw_cpe_string)
        if hw is None:
            return HardwareResult(
                input_cpe=hw_cpe_string, valid_input=False, unmatched=True,
                note="Could not parse as a CPE 2.3 formatted string.",
            )
        if hw.part != "h":
            return HardwareResult(
                input_cpe=hw_cpe_string, valid_input=False, unmatched=True,
                note=f"Expected part='h' (hardware), got part='{hw.part}'.",
            )

        result = HardwareResult(input_cpe=hw_cpe_string, valid_input=True)
        seen_cpe_names = set()

       
        version_hint = model_token_from_version(hw.version)

        for candidate in generate_rule_based_candidates(hw):
            result.candidates_tried += 1
            self._collect_exact(candidate, result, seen_cpe_names, version_hint, hw.version)

        required_tokens = tokenize_product(hw.product) | version_hint
        vendor_guesses = _all_vendor_guesses(hw.vendor)
        any_local_hit = False
        for vendor_guess in vendor_guesses:
            result.candidates_tried += 1
            local_hits = self.local_dict.search_by_tokens(
                part="o", vendor=vendor_guess, required_tokens=required_tokens,
                limit=self.keyword_search_limit,
            )
            local_hits = self._filter_and_cap(local_hits, version_hint, hw.version)
            if local_hits:
                any_local_hit = True
            for rec in local_hits:
                self._add_confirmed(result, rec, source="local_dictionary",
                                     matched_via=f"keyword_search:{vendor_guess}:{'+'.join(sorted(required_tokens))}",
                                     seen=seen_cpe_names)

        if not any_local_hit and self.api_client is not None and required_tokens:
            api_hits = self.api_client.search_keyword(
                f"{hw.vendor} {' '.join(sorted(required_tokens))}", limit=self.keyword_search_limit,
            )
            for prod in api_hits:
                self._add_confirmed_from_api(result, prod,
                                              matched_via=f"api_keyword_search:{'+'.join(sorted(required_tokens))}",
                                              seen=seen_cpe_names)

        if not result.confirmed_matches and required_tokens:
            for vendor_guess in vendor_guesses:
                result.candidates_tried += 1
                title_hits = self.local_dict.search_by_title_tokens(
                    part="o", vendor=vendor_guess, required_tokens=required_tokens,
                    limit=self.keyword_search_limit,
                )
                title_hits = self._filter_and_cap(title_hits, version_hint, hw.version)
                for rec in title_hits:
                    self._add_confirmed(
                        result, rec, source="local_dictionary_title_match",
                        matched_via=f"title_search:{vendor_guess}:{'+'.join(sorted(required_tokens))}",
                        seen=seen_cpe_names,
                    )

       

        result.unmatched = len(result.confirmed_matches) == 0
        if result.unmatched:
            result.note = (
                "No candidate Firmware/OS CPE could be confirmed against "
                "the local dictionary (including the title-text fallback)"
                + (" or the live NVD API" if self.api_client else "") + "."
            )
        return result

    # ------------------------------------------------------------------
    def _collect_exact(self, candidate: Candidate, result: HardwareResult, seen: set,
                        version_hint: frozenset = frozenset(), hw_version: str = "") -> None:
        # (a) exact concrete entries already known for this vendor/product
        local_hits = self.local_dict.entries_for("o", candidate.vendor, candidate.product)
        local_hits = self._filter_and_cap(local_hits, version_hint, hw_version)
        for rec in local_hits:
            self._add_confirmed(result, rec, source="local_dictionary",
                                 matched_via=candidate.rule, seen=seen)

        # (b) fall back to the live API only if offline lookup found nothing
        if not local_hits and self.api_client is not None:
            api_hits = self.api_client.search_keyword(f"{candidate.vendor} {candidate.product}", limit=10)
            for prod in api_hits:
                self._add_confirmed_from_api(result, prod, matched_via=candidate.rule, seen=seen)

    def _filter_and_cap(self, records: List[CpeRecord],
                         version_hint: frozenset = frozenset(),
                         hw_version: str = "") -> List[CpeRecord]:
       
        if not self.include_deprecated:
            active = [r for r in records if not r.deprecated]
            records = active if active else records
        if len(records) <= self.max_versions_per_product:
            return records

        if version_hint:
            related, others = [], []
            for r in records:
                if version_hint & (r.product_tokens | r.title_tokens):
                    related.append(r)
                else:
                    others.append(r)
        else:
            related, others = [], records

        others_by_recency = sorted(others, key=lambda r: (r.last_modified, r.created), reverse=True)
        hw_tuple = parse_version_tuple(hw_version) if (hw_version and not version_hint) else None
        if hw_tuple is not None:
            others_sorted = sorted(others_by_recency, key=lambda r: self._version_distance(hw_tuple, r))
        else:
            others_sorted = others_by_recency

        ordered, seen_names = [], set()
        for r in related + others_sorted:
            if r.cpe_name not in seen_names:
                seen_names.add(r.cpe_name)
                ordered.append(r)
        return ordered[: self.max_versions_per_product]

    @staticmethod
    def _version_distance(hw_tuple: Tuple[int, ...], record: CpeRecord) -> float:
        parsed = parse_cpe23(record.cpe_name)
        if parsed is None:
            return float("inf")
        rec_tuple = parse_version_tuple(parsed.version)
        if rec_tuple is None:
            return float("inf")
        n = max(len(hw_tuple), len(rec_tuple))
        a = hw_tuple + (0,) * (n - len(hw_tuple))
        b = rec_tuple + (0,) * (n - len(rec_tuple))
        dist, weight = 0.0, 1.0
        for x, y in zip(a, b):
            dist += abs(x - y) * weight
            weight /= 100.0
        return dist

    def _add_confirmed(self, result: HardwareResult, rec: CpeRecord, source: str,
                        matched_via: str, seen: set) -> None:
        if rec.cpe_name in seen:
            return
        seen.add(rec.cpe_name)
        result.confirmed_matches.append(ConfirmedMatch(
            cpe_name=rec.cpe_name, deprecated=rec.deprecated, title=rec.title,
            source=source, matched_via=matched_via,
        ))

    def _add_confirmed_from_api(self, result: HardwareResult, product_obj: dict,
                                 matched_via: str, seen: set) -> None:
        cpe_obj = product_obj.get("cpe", product_obj) if isinstance(product_obj, dict) else None
        if not isinstance(cpe_obj, dict):
            return
        cpe_name = cpe_obj.get("cpeName")
        if not cpe_name or cpe_name in seen:
            return
        if not self.include_deprecated and bool(cpe_obj.get("deprecated", False)):
            return
        parsed = parse_cpe23(cpe_name)
        if parsed is None or parsed.part != "o":
            return
        seen.add(cpe_name)
        titles = cpe_obj.get("titles") or []
        title = ""
        for t in titles:
            if t.get("lang") == "en":
                title = t.get("title", "")
                break
        if not title and titles:
            title = titles[0].get("title", "")
        result.confirmed_matches.append(ConfirmedMatch(
            cpe_name=cpe_name, deprecated=bool(cpe_obj.get("deprecated", False)),
            title=title, source="live_api", matched_via=matched_via,
        ))
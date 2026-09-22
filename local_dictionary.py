from __future__ import annotations
import glob
import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional

from cpe_utils import parse_cpe23, normalize_token

logger = logging.getLogger("cpe_pipeline.local_dictionary")


_MIN_TOKEN_LEN = 3
_FILLER_TOKENS = {"series", "firmware", "software", "image", "the", "and", "with", "for"}

_ROMAN_NUMERALS = {"i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii"}


def _is_significant_token(token: str) -> bool:
    if not token or token in _FILLER_TOKENS:
        return False
    if len(token) >= _MIN_TOKEN_LEN:
        return True
    if token in _ROMAN_NUMERALS:
        return True
   
    return any(c.isdigit() for c in token)


def tokenize_product(product: str) -> FrozenSet[str]:
   
    raw_tokens = re.split(r"[_\-\s]+", product.lower())
    return frozenset(t for t in raw_tokens if _is_significant_token(t))


def model_token_from_version(version: str) -> FrozenSet[str]:

    if not version or version in ("*", "-"):
        return frozenset()
    v = version.strip().lower()
    if "." in v or not re.fullmatch(r"[a-z0-9]{1,10}", v):
        return frozenset()
    return frozenset({v})


@dataclass
class CpeRecord:
    cpe_name: str
    deprecated: bool
    title: str
    part: str
    vendor: str
    product: str
    product_tokens: FrozenSet[str] = field(default_factory=frozenset)
    title_tokens: FrozenSet[str] = field(default_factory=frozenset)
    last_modified: str = ""
    created: str = ""


class LocalCpeDictionary:

    def __init__(self):
        self._exact: Dict[str, CpeRecord] = {}
        self._by_vpp: Dict[tuple, List[CpeRecord]] = defaultdict(list)
        self._by_pv: Dict[tuple, List[CpeRecord]] = defaultdict(list)
        self.loaded_chunks = 0
        self.record_count = 0


    def load_folder(self, folder: str, pattern: str = "nvdcpe-2.0-chunk-*.json") -> "LocalCpeDictionary":
        chunk_paths = sorted(glob.glob(os.path.join(folder, pattern)))
        if not chunk_paths:
            raise FileNotFoundError(
                f"No chunk files matching '{pattern}' found under '{folder}'. "
                f"Expected files like nvdcpe-2.0-chunk-0001.json .. chunk-0017.json."
            )
        for path in chunk_paths:
            self._load_chunk_file(path)
        logger.info(
            "Loaded %d chunk file(s), %d CPE records indexed.",
            self.loaded_chunks, self.record_count,
        )
        return self

    def _load_chunk_file(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Skipping unreadable chunk %s: %s", path, e)
            return

        for raw in self._iter_raw_records(data):
            self._index_record(raw)
        self.loaded_chunks += 1

    @staticmethod
    def _iter_raw_records(data) -> Iterable[dict]:
        """Recover the list of {"cpe": {...}} / {...} records regardless of
        the exact shape the chunk file was saved in."""
        if isinstance(data, dict) and "products" in data:
            yield from data["products"]
        elif isinstance(data, list):
            yield from data
        elif isinstance(data, dict) and "cpe" in data:
            yield data
        else:
            logger.debug("Unrecognized chunk shape, no records recovered.")

    def _index_record(self, raw: dict) -> None:
        cpe_obj = raw.get("cpe", raw) if isinstance(raw, dict) else None
        if not isinstance(cpe_obj, dict):
            return
        cpe_name = cpe_obj.get("cpeName")
        if not cpe_name:
            return
        parsed = parse_cpe23(cpe_name)
        if parsed is None:
            return
        titles = cpe_obj.get("titles") or []
        title = self._pick_title(titles)
        vendor_n = normalize_token(parsed.vendor)
        product_n = normalize_token(parsed.product)
        record = CpeRecord(
            cpe_name=cpe_name,
            deprecated=bool(cpe_obj.get("deprecated", False)),
            title=title,
            part=parsed.part,
            vendor=vendor_n,
            product=product_n,
            product_tokens=tokenize_product(product_n),
            title_tokens=tokenize_product(title.lower()) if title else frozenset(),
            last_modified=cpe_obj.get("lastModified", "") or "",
            created=cpe_obj.get("created", "") or "",
        )
        self._exact[cpe_name] = record
        self._by_vpp[(record.part, record.vendor, record.product)].append(record)
        self._by_pv[(record.part, record.vendor)].append(record)
        self.record_count += 1

    @staticmethod
    def _pick_title(titles: list) -> str:
       
        for t in titles:
            if t.get("lang") == "en":
                return t.get("title", "")
        return titles[0].get("title", "") if titles else ""

 
    def exact_exists(self, cpe_name: str) -> Optional[CpeRecord]:
        return self._exact.get(cpe_name)

    def entries_for(self, part: str, vendor: str, product: str) -> List[CpeRecord]:
      
        return list(self._by_vpp.get((part, normalize_token(vendor), normalize_token(product)), []))

    def near_matches(self, part: str, vendor: str, required_tokens: FrozenSet[str],
                      min_shared: int = 1, limit: int = 10) -> List[tuple]:
      
        vendor_n = normalize_token(vendor)
        scored = []
        for record in self._by_pv.get((part, vendor_n), []):
            shared = required_tokens & record.product_tokens
            if len(shared) >= min_shared:
                extra = record.product_tokens - required_tokens
                missing = required_tokens - record.product_tokens
                scored.append((record, shared, extra, missing))
        scored.sort(key=lambda x: len(x[1]), reverse=True)
        return scored[:limit]

    def search_by_tokens(self, part: str, vendor: str, required_tokens: FrozenSet[str],
                          limit: int = 25) -> List[CpeRecord]:

        if not required_tokens:
            return []
        vendor_n = normalize_token(vendor)
        hw_records = self._by_pv.get(("h", vendor_n), [])
        results: List[CpeRecord] = []
        for record in self._by_pv.get((part, vendor_n), []):
            if not required_tokens <= record.product_tokens:
                continue  
            extra = record.product_tokens - required_tokens
            if any(any(c.isdigit() for c in t) for t in extra):
                continue  
            if extra and self._extra_belongs_to_more_specific_hardware(required_tokens, extra, hw_records):
                continue  

            results.append(record)
            if len(results) >= limit:
                break
        return results

    def search_by_title_tokens(self, part: str, vendor: str, required_tokens: FrozenSet[str],
                                limit: int = 25) -> List[CpeRecord]:
    
        if not required_tokens:
            return []
        vendor_n = normalize_token(vendor)
        hw_records = self._by_pv.get(("h", vendor_n), [])
        results: List[CpeRecord] = []
        for record in self._by_pv.get((part, vendor_n), []):
            if not required_tokens <= record.title_tokens:
                continue  
            extra = record.title_tokens - required_tokens
            if extra and self._extra_belongs_to_more_specific_hardware(required_tokens, extra, hw_records):
                continue
            results.append(record)
            if len(results) >= limit:
                break
        return results

    @staticmethod
    def _extra_belongs_to_more_specific_hardware(required_tokens: FrozenSet[str], extra: FrozenSet[str],
                                                   hw_records: List["CpeRecord"]) -> bool:
       
        combined = required_tokens | extra
        for hw in hw_records:
            if combined <= hw.product_tokens:
                return True
        return False
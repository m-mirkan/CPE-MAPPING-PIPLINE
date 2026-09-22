from __future__ import annotations
import re
from dataclasses import dataclass, replace
from typing import Optional, Tuple

CPE_FIELDS = [
    "cpe_version", "part", "vendor", "product", "version", "update",
    "edition", "language", "sw_edition", "target_sw", "target_hw", "other",
]


@dataclass
class CpeComponents:
    part: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def to_string(self) -> str:
        return "cpe:2.3:" + ":".join([
            self.part, self.vendor, self.product, self.version, self.update,
            self.edition, self.language, self.sw_edition, self.target_sw,
            self.target_hw, self.other,
        ])


def parse_cpe23(cpe_string: str) -> Optional[CpeComponents]:
    """Parse a cpe:2.3:... string into its components. Returns None if the
    string doesn't look like a well-formed CPE 2.3 FS."""
    if not cpe_string or not cpe_string.startswith("cpe:2.3:"):
        return None
    parts = cpe_string.split(":")

    if len(parts) < 13:
        parts = parts + ["*"] * (13 - len(parts))
    _, _, part, vendor, product, version, update, edition, language, \
        sw_edition, target_sw, target_hw, other = parts[:13]
    return CpeComponents(
        part=part, vendor=vendor, product=product, version=version,
        update=update, edition=edition, language=language,
        sw_edition=sw_edition, target_sw=target_sw, target_hw=target_hw,
        other=other,
    )


def with_part(components: CpeComponents, part: str) -> CpeComponents:
    return replace(components, part=part)


def normalize_token(token: str) -> str:
    return (token or "").strip().lower()


def parse_version_tuple(version: str) -> Optional[Tuple[int, ...]]:

    if not version or version in ("*", "-"):
        return None
    digit_groups = re.findall(r"\d+", version)
    if not digit_groups:
        return None
    return tuple(int(g) for g in digit_groups)
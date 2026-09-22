from __future__ import annotations
import re
from typing import List, NamedTuple, Set

from cpe_utils import CpeComponents, normalize_token
from local_dictionary import model_token_from_version


class Candidate(NamedTuple):
    vendor: str
    product: str
    rule: str  # which rule produced it, for traceability


VENDOR_ALIASES = {
    "konica_minolta": ["konica_minolta", "konicaminolta"],
    "avocent": ["avocent", "emerson", "vertiv"],
    "3com": ["3com", "hp", "hewlett_packard_enterprise", "hpe"],
    "compaq": ["compaq", "hp", "hewlett_packard"],
    "digital_equipment_corporation": ["digital_equipment_corporation", "dec", "compaq", "hp"],
    "foundry": ["foundry", "foundry_networks", "brocade"],
    "brocade": ["brocade", "broadcom"],
    "nortel": ["nortel", "nortel_networks", "avaya"],
    "motorola": ["motorola", "motorola_solutions", "zebra"],
    "sourcefire": ["sourcefire", "cisco"],
    "isilon": ["isilon", "emc", "dell", "dellemc", "dell_emc"],
    "netscreen": ["netscreen", "juniper"],
    "colubris": ["colubris", "hp"],
    "procurve": ["procurve", "hp", "hpe", "aruba"],
    "tippingpoint": ["tippingpoint", "tipping_point", "hp", "trendmicro", "trend_micro"],
    "riverstone": ["riverstone", "riverstone_networks", "lucent", "alcatel-lucent", "alcatel_lucent"],
    "cyclades": ["cyclades", "avocent", "vertiv"],
    "linksys": ["linksys", "cisco", "belkin"],
    "3par": ["3par", "hp", "hpe"],
    "aruba": ["aruba", "aruba_networks", "hp", "hpe"],
    "sun": ["sun", "sun_microsystems", "oracle"],
    "netapp": ["netapp", "network_appliance"],
    "mcafee": ["mcafee", "intel", "trellix"],
    "ca_technologies": ["ca_technologies", "ca", "broadcom"],
    "symantec": ["symantec", "broadcom"],
}


def _vendor_spelling_variants(vendor: str) -> Set[str]:
    v = normalize_token(vendor)
    if not v:
        return set()
    variants = {
        v,
        v.replace("-", "_"),
        v.replace("_", "-"),
        v.replace("_", "").replace("-", ""),
        v.replace("_", " ").replace("-", " ").strip(),
    }
    return {x for x in variants if x}


def _acquisition_group(vendor: str) -> List[str]:
    v = normalize_token(vendor)
    for group in VENDOR_ALIASES.values():
        if v in group:
            return group
    return [v]


def _all_vendor_guesses(vendor: str) -> Set[str]:
    guesses: Set[str] = set()
    for base in _acquisition_group(vendor):
        guesses |= _vendor_spelling_variants(base)
    return guesses


_PRODUCT_SUFFIXES = [
    "",             
    "_firmware",
    "_fw",
    "_os",
    "_software",
    "_firmware_image",
]


def _strip_trailing_revision(product: str) -> List[str]:
   
    variants = [product]
    if product.endswith("_series"):
        variants.append(product[: -len("_series")])
    return list(dict.fromkeys(variants))


def _samsung_build_code_bases(hw: CpeComponents) -> List[str]:

    if normalize_token(hw.vendor) not in ("samsung",):
        return []
    segments = re.split(r"[_\-\s]+", hw.product.lower())
    if not segments:
        return []
    last = segments[-1]
    if re.fullmatch(r"[a-z]{2}\d{2,4}[a-z]?", last):
        return [last]
    return []


def rule_generic_fallback(hw: CpeComponents) -> List[Candidate]:
  
    vendors = _all_vendor_guesses(hw.vendor)
    product_bases = _strip_trailing_revision(hw.product)

    version_token = model_token_from_version(hw.version)
    if version_token:
        (model_num,) = version_token
        product_bases = list(dict.fromkeys(
            product_bases + [f"{hw.product}_{model_num}", f"{hw.product}{model_num}"]
        ))

    product_bases = list(dict.fromkeys(product_bases + _samsung_build_code_bases(hw)))

    candidates = []
    for v in vendors:
        for base in product_bases:
            for suffix in _PRODUCT_SUFFIXES:
                candidates.append(Candidate(
                    vendor=v, product=f"{base}{suffix}",
                    rule="generic_vendor_x_suffix",
                ))
    return candidates



_FIXED_OS_BY_VENDOR = {
  
    "netscreen": ["screenos"],

    "fortinet": ["fortios"],
    "paloaltonetworks": ["pan-os"],
    "checkpoint": ["gaia_os"],
    "arubanetworks": ["arubaos"],
    "extremenetworks": ["exos"],
    "f5": ["big-ip"],
}


_FIREPOWER_CHASSIS_PATTERN = re.compile(r"^firepower_(41\d\d|93\d\d)$")
_FIREPOWER_CHASSIS_OS = [
    "firepower_extensible_operating_system",
    "fxos",
    "fx-os",
    "adaptive_security_appliance_software",
]


_JUNIPER_FAMILY_OS = [
    (re.compile(r"^srx"), ["junos"]),
    (re.compile(r"^ex\d"), ["junos"]),
    (re.compile(r"^mx\d"), ["junos"]),
    (re.compile(r"^qfx"), ["junos", "junos_os_evolved"]),
    (re.compile(r"^acx"), ["junos", "junos_os_evolved"]),
    (re.compile(r"^ptx"), ["junos_os_evolved", "junos"]),
]


def _juniper_os_products(product: str) -> List[str]:
    p = normalize_token(product)
    for pattern, products in _JUNIPER_FAMILY_OS:
        if pattern.match(p):
            return products
  
    return ["junos", "junos_os_evolved"]


def rule_fixed_os(hw: CpeComponents) -> List[Candidate]:
    vendor_key = normalize_token(hw.vendor).replace("_", "").replace("-", "").replace(" ", "")
    if vendor_key == "juniper":
        products = _juniper_os_products(hw.product)
        return [Candidate(vendor=hw.vendor, product=p, rule="fixed_os_juniper") for p in products]
    if vendor_key == "cisco" and _FIREPOWER_CHASSIS_PATTERN.match(normalize_token(hw.product)):
        return [Candidate(vendor=hw.vendor, product=p, rule="fixed_os_cisco_firepower_chassis")
                for p in _FIREPOWER_CHASSIS_OS]
    products = _FIXED_OS_BY_VENDOR.get(vendor_key)
    if not products:
        return []
    return [Candidate(vendor=hw.vendor, product=p, rule=f"fixed_os_{vendor_key}") for p in products]


def generate_rule_based_candidates(hw: CpeComponents) -> List[Candidate]:
    candidates: List[Candidate] = []
    candidates.extend(rule_fixed_os(hw))
    candidates.extend(rule_generic_fallback(hw))
    seen = set()
    unique = []
    for c in candidates:
        key = (normalize_token(c.vendor), normalize_token(c.product))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique
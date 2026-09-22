## Files

- `cpe_utils.py` - parse/build cpe:2.3 strings
- `local_dictionary.py` - loads the 17 chunk files into memory, builds fast lookup tables (by vendor+product, by vendor, and by title tokens)
- `vendor_rules.py` - generates candidate (vendor, product) guesses (spelling variants, acquisitions table, suffix patterns, fixed-OS cases like Juniper/Junos, Cisco Firepower chassis/FXOS)
- `nvd_api_client.py` - optional live API fallback, rate-limited, only used if `--use-api`
- `candidate_validator.py` - checks every guess against the dictionary/API, keeps only confirmed matches; also ranks/caps by version-closeness to the hardware's own version when it has one
- `pipeline.py` - reads input, runs everything, writes the output files
- `cve_groundtruth.py` - mines the yearly `nvdcve-2.0-YYYY.json` CVE dumps for cases where a hardware CPE and a firmware/OS CPE are listed together in the same CVE configuration, and builds `groundtruth_dataset.json` from those co-occurrences. Only accepts a pair when the two CPEs share a vendor or a known rebrand/acquisition (reuses `vendor_rules.py`'s alias table), which is what keeps broad multi-vendor advisories from producing fabricated cross-vendor pairings.
- `evaluate_matches.py` - scores `Outputs/matched_cpes.json` against `groundtruth_dataset.json` and writes `Outputs/test_results.json`
- `main.py` - CLI, defaults already point at Data/ and Outputs/

## Run it (Windows)

Open the `task2_cpe_mapping` folder, open a terminal there (address bar -> type `cmd` -> Enter), then:

```
python main.py --build-groundtruth --diagnose-unmatched --evaluate
```

## Output

- `Outputs/matched_cpes.json` - every hardware CPE that got at least one confirmed firmware/OS match, with the confirmed CPEs listed (`source` can be `local_dictionary`, `local_dictionary_title_match`, or `live_api`)
- `Outputs/unmatched_log.json` - every hardware CPE with zero confirmed matches, with a note why (couldn't parse, or nothing found even after the title fallback)
- `Outputs/near_misses.json` - only written with `--diagnose-unmatched`. For each unmatched CPE, up to 5 loosely-related dictionary entries with `shared_tokens`/`missing_tokens`/`extra_tokens` shown, so we can tell at a glance whether it's a real "not in the dictionary" or a naming pattern worth adding a rule for. An unmatched entry with no near-miss listed almost certainly just isn't in the dictionary.
- `Outputs/groundtruth_dataset.json` - only written with `--build-groundtruth`. List of `{"hardware_cpe", "os_firmware_cpes": [...], "source_cves": [...]}` mined from the CVE dumps.
- `Outputs/test_results.json` - only written with `--evaluate`. `{"summary": {...}, "per_entry": [...]}`
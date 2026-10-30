# ioc-extractor

A Claude skill that turns a threat intelligence report (PDF or HTML) into a validated JSON file of indicators of compromise (IOCs) that hunting tools can match against your environment.

This document is for the people who **maintain** the skill. The instructions Claude follows when it runs the skill are in [`SKILL.md`](SKILL.md); analysts never need to read either file.

---

## Contents

1. [What the skill does](#1-what-the-skill-does)
2. [Design: why a script and a model](#2-design-why-a-script-and-a-model)
3. [Folder layout](#3-folder-layout)
4. [How a run works](#4-how-a-run-works)
5. [File reference](#5-file-reference)
6. [Data formats](#6-data-formats)
7. [Safety rules](#7-safety-rules)
8. [Maintenance](#8-maintenance)
9. [Testing and validation](#9-testing-and-validation)
10. [Known limits](#10-known-limits)
11. [Change history](#11-change-history)

---

## 1. What the skill does

**Input:** a report the analyst supplies as a PDF or HTML file. IOCs that appear only in images (screenshots of tables, scanned pages) are transcribed by Claude into a text file and processed the same way.

**Output:** one JSON file, plus an inline summary for the analyst:

| Section | Contents |
|---|---|
| `iocs` | Indicators grouped by type: `ipv4`, `ipv6`, `cidr_ipv4`, `cidr_ipv6`, `domain`, `fqdn`, `url`, `email`, `md5`, `sha1`, `sha256`, `sha512`, `filename`, `filepath`, `registry_key` |
| `cves` | CVE IDs the report references (kept apart, because they are not IOCs) |
| `excluded` | Everything found but not reported, with the reason, so analysts can audit the decisions |
| `needs_review` | Values that failed validation, for example a hash with a wrong length |
| `warnings` | Processing notes such as an unreadable input or no IOCs found |

Every value is **refanged** (`hxxp://evil[.]com` → `http://evil.com`), normalized and deduplicated, so it can be matched directly against SIEM, EDR or proxy data.

**Scope:** extraction only. The skill never fetches content, looks up indicators, hunts or blocks. Other skills and MCP tools in the workflow consume its JSON.

---

## 2. Design: why a script and a model

The work is split deliberately:

| Component | Responsible for | Why |
|---|---|---|
| **Script** (`scripts/extract_iocs.py`) | Every indicator *value*: refanging, extraction, normalization, validation, fixed exclusions, output | A language model regenerates long strings rather than copying them. One changed character in a hash makes it useless and still looks valid. The script copies characters exactly. |
| **Claude** (following `SKILL.md`) | Every *judgment*: is this an indicator, what confidence, what type, what did the patterns miss | A pattern can't tell a C2 server from a citation, or a dropped file from a stock Windows tool. |

The two meet through a strict contract: **Claude never types an indicator value.** It refers to candidates by ID. The only exceptions, OCR transcriptions and *additions* (values the script missed), are verified by the script against the source text before they're accepted.

```
 report.pdf / report.html ─┐
 ocr.txt (optional) ───────┤
                           ▼
              ┌─────────────────────────┐
              │ extract (script)        │  refang, extract, validate,
              │ → candidates.json       │  apply rule exclusions, add hints
              └────────────┬────────────┘
                           ▼
              ┌─────────────────────────┐
              │ review (Claude)         │  keep / exclude / confidence / type,
              │ → decisions.json        │  additions for missed values
              └────────────┬────────────┘
                           ▼
              ┌─────────────────────────┐
              │ finalize (script)       │  enforce rules, verify additions,
              │ → iocs_<…>.json         │  build schema-valid output
              └─────────────────────────┘
```

---

## 3. Folder layout

```
ioc-extractor/
├── SKILL.md                      Core instructions Claude follows (workflow, core review rules, safety rules), ~10 KB
├── README.md                     This document (for maintainers)
├── references/
│   └── review-guide.md           Harder review cases by topic; Claude opens a section only when it needs it
├── scripts/
│   ├── extract_iocs.py           Extraction engine: `extract` and `finalize` commands
│   └── update_data.py            Refreshes the bundled domain reference data
├── schema/
│   └── ioc_output.schema.json    JSON Schema of the output: the contract with downstream tools
├── data/
│   ├── guidance.json             Review guidance per note code; extract copies the relevant entries into candidates.json
│   ├── public_suffix_list.dat    Public Suffix List (decides domain versus FQDN)
│   └── tlds.txt                  Valid top-level domains (1,448 plus .onion)
└── tests/
    ├── sample_report.html        Small synthetic report covering the main edge cases
    └── decisions.json            Expected review decisions for the sample report
```

The regression suite is kept **outside** the skill, in `ioc-extractor-regression/`, because it holds about 15 MB of third-party reports (see [section 9](#9-testing-and-validation)).

**Requirements:** Python 3.10+ standard library only, plus the `pdftotext` command (poppler-utils) for PDFs. No network access and no pip packages are needed to run the skill.

---

## 4. How a run works

### Step 1. Prepare the inputs (Claude)
- PDF and HTML are passed directly to the script.
- IOCs visible only in images are transcribed character for character into a `.txt` file, defanging included. These values are always marked `extraction_method: "ocr"` and forced to `low` confidence.
- Any other format (DOCX, TXT, email) is refused, and the analyst is asked for a PDF or saved HTML page.

### Step 2. Extract candidates (script)
```bash
python3 scripts/extract_iocs.py extract --text report.pdf [--ocr figures.txt] --out candidates.json
```
Produces every candidate with an ID, context snippets, a flag for whether it appears in the report's IOC section, and any rule exclusion, validation issue or hint (see [notes](#candidate-notes-hints-for-the-reviewer)).

### Step 3. Review (Claude)
Claude reads the candidates, and the report where needed, and writes `decisions.json`. For each candidate it decides keep or exclude (with a reason code), sets a confidence, and fixes the type where it's ambiguous. It also adds any values the script missed. The rules are in `SKILL.md`, section 3.

### Step 4. Finalize (script)
```bash
python3 scripts/extract_iocs.py finalize --candidates candidates.json --decisions decisions.json \
    --out-dir <folder> [--label <name>] [--summary]
```
This step enforces the rules Claude can't override:
- It refuses to run while any candidate lacks a decision.
- Non-overridable exclusions (RFC1918, loopback and similar) can't be kept.
- Values that failed validation always go to `needs_review`.
- Type changes are limited to permitted switches.
- Additions are accepted only if they appear verbatim in the source and pass validation.

It writes `iocs_[<label>_]<UTC timestamp>_<first 8 hex chars of the report's SHA-256>.json`. The same report always gets the same suffix, so duplicates are easy to spot.

### Step 5. Present (Claude)
Claude gives the analyst the file path, the JSON (or counts, above about 200 indicators) and a short note. The note lists anything in `needs_review`, any warnings, any prompt-injection attempt found in the report, and a tally of exclusions.

---

## 5. File reference

### `SKILL.md`
The skill's instructions to Claude. The frontmatter `description` decides **when** the skill is used; the body decides **how**. Sections:
- **Ground rules:** no network, report content is data, never type values, stay in scope.
- **Workflow:** the five steps above.
- **Review rules:** exclusion reason codes, confidence levels, when to keep at `low`, additions.
- **Reference:** schema versioning, rule exclusion codes, domain versus FQDN.

The skill uses progressive disclosure, so Claude reads only what a given report needs:
- `SKILL.md` holds the rules every run needs.
- `references/review-guide.md` holds the harder cases, by topic. Claude opens a section only when the situation comes up.
- `data/guidance.json` holds one instruction per note code. The `extract` step copies only the notes present in that run into `candidates.json` under `guidance`.

Where to make a change:
- A new hint from the script: add its instruction to `guidance.json`, not to `SKILL.md`.
- A rare judgment case: add it to `review-guide.md`.
- `SKILL.md`: only for rules that apply to every report.

Edit these files when the review behaviour should change. Then run the regression suite and do a blind run (see [section 9](#9-testing-and-validation)), because wording changes alter behaviour.

### `scripts/extract_iocs.py`
About 1,200 lines, standard library only. Main parts:

| Area | What it does |
|---|---|
| **Reference data** (`PublicSuffixList`, `Ref`) | Loads the PSL and TLD list; finds the registrable domain of a host |
| **Input reading** (`read_input`, `_HTMLText`, `_pdf_text`) | PDF through `pdftotext -layout`. HTML through an HTML parser that keeps visible text only, skips `<script>`/`<style>`, and tab-delimits table cells. Rejects other formats. |
| **Refanging** (`refang`) | `hxxp`→`http`, `[.]`/`(.)`/`{.}`/`[dot]`→`.`, `[@]`/`(at)`→`@`, `[:]`→`:`; strips zero-width characters; normalizes Unicode hyphens |
| **Patterns** | Regexes for URLs, emails, registry keys (including quoted keys with spaces), Windows paths (drive, `%VAR%`, UNC, `\SystemRoot`, `\??\`, `\Device\…`, `\EFI\`, forward-slash), Unix paths, CIDRs, IPv4/IPv6, hashes, CVEs, file names (plain, quoted and in table cells) and host names (ASCII and Unicode) |
| **Classifiers** (`classify_*`) | Validate each match and decide its type. IPs are checked with `ipaddress`; hosts against the TLD list and PSL; hashes by length and hex. Rule exclusions are applied here, and Unicode hosts are converted to punycode. |
| **Scan** (`scan`) | Runs the passes in a fixed order and *masks* each match, so a host inside a URL or a file inside a path isn't reported twice. Detects the IOC section (start heading to end heading). Attaches hints. |
| **Hint helpers** | `_looks_wrapped`, `_path_looks_wrapped`, `_continues_previous_line`, `_path_continues_after_space`, `_looks_like_code`, `_in_rule_or_code`, `_hash_continues_url`, `_looks_like_section_number`, and the hash-of-a-name and key/parameter patterns |
| **`cmd_extract`** | Reads inputs, runs the scan, writes `candidates.json`, prints a summary |
| **`cmd_finalize`** | Applies decisions, enforces the rules above, verifies additions with `_found_in_source`, writes the output |
| **`_found_in_source`** | Checks that an addition appears in the source, tolerating line wraps, end-of-line hyphens and table cells split across up to four lines |

### `scripts/update_data.py`
Downloads a fresh Public Suffix List and the IANA TLD list. If IANA isn't reachable, it derives the TLD list from the PSL (which is what the bundled `tlds.txt` was built from). Run it occasionally (monthly is plenty) on a machine with outbound access to `publicsuffix.org` and `data.iana.org`. It's the only part of the skill that uses the network, and it never runs during an extraction.

```bash
python3 scripts/update_data.py            # download both lists
python3 scripts/update_data.py --offline  # rebuild tlds.txt from the bundled PSL only
```

### `schema/ioc_output.schema.json`
JSON Schema (draft 2020-12) for the output file. It's the contract with downstream skills and MCP tools. Every top-level key and every `iocs` type is always present (empty arrays when there's nothing to report). Each type has a value pattern (for example `sha256` is 64 lowercase hex characters). `schema_version` follows semantic versioning; see [change history](#11-change-history).

### `data/public_suffix_list.dat` and `data/tlds.txt`
Bundled so domain validation works offline, including in claude.ai's sandbox. The PSL decides whether `cdn.evil.co.uk` is an FQDN under the registrable domain `evil.co.uk`. The TLD list rejects strings like `invoice.dll` as domains because `.dll` isn't a TLD, while still recognising `.zip`, `.mov` and `.run`, which are.

### `tests/sample_report.html` and `tests/decisions.json`
A small synthetic report that exercises the main behaviours: defanged values, private and documentation IPs, a version string, a truncated hash, a file name that's also a domain (`docs.zip`), registry keys and paths, an injected "ignore all previous instructions" line, and a URL inside a `<script>` tag that must be ignored. Run it as a quick smoke test:
```bash
python3 scripts/extract_iocs.py extract --text tests/sample_report.html --out /tmp/c.json
python3 scripts/extract_iocs.py finalize --candidates /tmp/c.json --decisions tests/decisions.json --out-dir /tmp --summary
# expect 21 IOCs, 16 excluded, 1 needs review, and a warning about a rejected addition
```

---

## 6. Data formats

### `candidates.json` (written by `extract`)
```json
{
  "input_sha256": "…", "inputs": [{"path": "…", "method": "text", "ioc_section_detected": true}],
  "summary": {"candidates": 217, "needs_decision": 216, "rule_excluded": 0, "validation_issues": 1, "cves": 0,
              "guidance_for": ["possibly_continues_on_next_line", "version_string"]},
  "guidance": {"possibly_continues_on_next_line": "The URL, path or registry key may be cut at a line break…"},
  "candidates": [{
    "id": "c0004", "type": "ipv4", "value": "45.133.216.14",
    "extraction_method": "text", "occurrences": 2, "in_ioc_section": true,
    "contexts": ["…falls back to 45.133.216.14:8443…"],
    "rule_exclusion": {"reason": "version_string", "overridable": true},
    "validation_issue": "invalid_length:63_expected_64",
    "ambiguous_types": ["filename", "hostname"],
    "notes": ["possibly_continues_on_next_line"]
  }],
  "cves": [{"id": "v0001", "type": "cve", "value": "CVE-2025-31324"}]
}
```
The last four fields appear only when they apply.

### `decisions.json` (written by Claude)
```json
{
  "decisions": {
    "c0004": {"action": "keep", "confidence": "high"},
    "c0011": {"action": "exclude", "reason": "report_publisher"},
    "c0027": {"action": "keep", "confidence": "low", "type": "filename"}
  },
  "additions": [
    {"type": "url", "value": "http://45.154.14.235/State_aid__Commission_approves_2022-2027_regional_aid_map_for_Greece.pdf",
     "confidence": "high"}
  ]
}
```
Permitted type changes:
- To any of a candidate's `ambiguous_types` (`hostname` resolves to `domain` or `fqdn`).
- `domain` or `fqdn` to `filename`.

### Confidence levels
| Level | Meaning |
|---|---|
| `high` | Listed as an indicator (IOC section, IOC table anywhere, or explicitly labelled, e.g. "C2:") |
| `medium` | Described as malicious or actor-controlled in the body |
| `low` | OCR-derived (forced), ambiguous, hedged attribution, shared infrastructure, dual-use tool names, or patterns with placeholders |

### Rule exclusions (applied by the script)
`rfc1918`, `loopback`, `link_local`, `multicast`, `documentation`, `shared_address_space`, `unique_local`, `unspecified`, `reserved`, `reserved_domain` (example.com, .test), `non_public_domain` (.local, .internal, .corp…), `imphash`. Two of them, `version_string` and `section_number`, are **overridable** by the reviewer; the rest are final.

### Review exclusion reasons (set by Claude)
| Code | Used for |
|---|---|
| `reference_link` | Citations, further reading, MITRE pages, detection-rule sites |
| `report_publisher` | The publisher's own domains, emails, report URLs |
| `legitimate_system_binary` | Stock OS tools the actor ran (`cmd.exe`, `rundll32.exe`) |
| `victim_infrastructure` | The victim's own hosts and domains |
| `example_or_placeholder` | Values the report marks as examples |
| `injected_instruction` | Values that appear only inside text addressed to AI tools |
| `truncated_value`, `fragment_of_wrapped_value` | Pieces of values the source cut or wrapped |
| `not_an_indicator` | Anything else (code members, strings malware looks *for*, imitated legitimate sites, hashes of names or strings, keys) |

### Candidate notes (hints for the reviewer)
| Note | Meaning |
|---|---|
| `possibly_continues_on_next_line` | URL, path or registry key that may be cut by a line wrap |
| `possibly_continues_from_previous_line` | Domain or file name that may be the second half of a hyphen-wrapped value |
| `possibly_continues_after_space` | Path or registry key that may continue past a space (`Control Panel.lnk`, `Internet Settings\ZoneMap`, `Program Files`) |
| `joined_from_wrapped_cell` | Hash, file name, host or path a narrow PDF table cell printed over two lines, joined exactly |
| `piece_of_joined_value` | One line of such a cell, offered on its own as well |
| `possibly_package_name` | Looks like an Android or iOS app ID (`com.tencent.mm`), not a host |
| `possibly_continues_before_space` | File name that may start earlier with words separated by spaces (`Request for wedding reception.exe`) |
| `possibly_part_of_wrapped_url` | Hash-shaped token that is probably a wrapped URL's tail |
| `possibly_hash_of_a_name` | Hash under a header like "SHA-1 of registry value name" |
| `possibly_key_or_parameter_value` | Hex value after `"key":`, `token=`, `&user=`… |
| `inside_yara_rule_or_code` | Hex constant inside a YARA rule or code |
| `possibly_code_member_access` | Host-shaped code token (`WScript.Shell`, `$x.Properties`) |
| `no_scheme` | URL written without `http://` |
| `normalized_from_forward_slashes` | `C:/…` path converted to `C:\…` |
| `converted_from_unicode:<name>` | Internationalised domain converted to punycode |
| `possibly_detection_name` | Host-shaped token from an AV detection name (`Win64/Winnti.BN`) |
| `wildcard_url_reservation` | HTTP.sys listener URL with a `+` or `*` host (`http://+:443/requested`) |
| `relative_path`, `no_extension` | Reviewer additions accepted under the relaxed rules |
| `possibly_first_part_of_split_hash` | MD5/SHA1-length piece of a longer hash printed over two lines of a table cell |
| `inside_url` | Hash-shaped path segment of a URL on the same line |
| `possibly_certificate_thumbprint` | Hash labelled as a certificate thumbprint, fingerprint or serial |
| `page_header_or_footer` | Line repeated at the top or bottom of several printed pages |
| `inside_user_agent` | Bot-information URL inside a crawler User-Agent |
| `port:N` | IP written with a port; the schema has no port field |
| `unescaped_string_literal` | Path written with doubled backslashes (code string), reported unescaped |
| `no_hive` | Registry key given without its hive (schema 2.1.0) |
| `wildcard_subdomains` | The report wrote `*.domain`; the domain is offered with this note |
| `part_of_file_name` | Hash glued into a file name (`<hash>_se.exe`), often the sample's own hash |
| `wildcard_pattern` | Reviewer addition with `*` or `?` wildcards, kept as a hunting pattern |
| `derived_from_url` | Host (IP, domain or FQDN) the report gives only inside URLs; offered as its own candidate, written with `derived_from` when kept (schema 2.2.0) |
| `nt_registry_path` | Registry key in kernel form, `\REGISTRY\MACHINE\...` (schema 2.1.0) |
| `encoded_ip_host:a.b.c.d` | URL whose host is an IP written as a single number |
| `root_relative_path`, `contains_placeholder` | Reviewer additions such as `\inetpub\wwwroot\aspnet_client` or `\<exchange install path>\...` |
| `hash_table_name` | Extensionless name taken from the file-name column next to a hash in an HTML table (also carries `no_extension`) |

### Warnings
`input_unreadable`, `no_text_extracted` (scanned PDF: transcribe it), `ocr_input_present`, `no_iocs_found`, `addition_not_found_in_source`, `addition_failed_validation`, `addition_unknown_type`, `addition_check_unreadable_input`, `input_changed_since_extract`, `decision_for_unknown_id`.

---

## 7. Safety rules

These are enforced both in `SKILL.md` and, where possible, in code:

| Risk | Control |
|---|---|
| Leaking partner (TLP:AMBER/RED) indicators | No network access during extraction; no lookups or enrichment |
| Prompt injection inside a report | `SKILL.md` treats report content as data only. Injected values are excluded as `injected_instruction` and reported to the analyst. Tested with a planted visible paragraph and hidden `display:none` text. |
| Mistyped or invented values | Claude never types values; additions are verified against the source; hashes are length- and hex-checked |
| Private or reserved addresses reaching hunt tools | Non-overridable rule exclusions in the script |
| Silent data loss | Nothing is dropped without a record: every exclusion appears in `excluded` with its reason |

---

## 8. Maintenance

| Task | How |
|---|---|
| Refresh domain data | `python3 scripts/update_data.py` (monthly), then run the regression suite |
| Change extraction behaviour | Edit `extract_iocs.py`, then run the regression suite and review every diff |
| Change review behaviour | Edit `SKILL.md` (every run), `references/review-guide.md` (rare cases) or `data/guidance.json` (a note's instruction), then run the suite plus at least one blind run |
| Add a new hint (note) in the script | Emit the note in `extract_iocs.py` and add its instruction to `data/guidance.json` |
| Add an output field | Update the schema, bump `SCHEMA_VERSION` (minor for additions, major for anything breaking), tell the owners of downstream tools |
| Investigate an analyst complaint | Add the report as a regression case (section 9), reproduce, fix, accept the baseline |

---

## 9. Testing and validation

### Regression suite (`ioc-extractor-regression/`, kept outside the skill)
**65 cases**: 61 real reports from 20 publishers (Cisco Talos, ESET, Kaspersky, CISA, 360, The DFIR Report, Unit 42, Recorded Future, Volexity, Bitdefender, Citizen Lab, Microsoft, Sophos, Proofpoint, Trend Micro, Check Point, JPCERT, CERT-UA, Positive Technologies, NCC Group; CISA/NSA/FBI joint advisory; one Japanese article and one scanned PDF), 2 screenshot tests, a planted-injection test and the sample report, covering 3,491 ground-truth indicators. Each case holds the report, an answer key, review decisions keyed by value, and an accepted baseline.

```bash
python3 run.py --skill ../ioc-extractor          # run all cases
python3 run.py --skill ../ioc-extractor -k cisa  # run some cases
python3 run.py --skill ../ioc-extractor --update # accept a reviewed diff
```
A case fails on a recall drop, a new candidate with no review decision, a finalize or schema error, or any difference from its baseline.

**Ground truth comes from two kinds of source:**
- **Vendor IOC files published online** (12 cases, most independent): ESET `malware-ioc`, Cisco Talos `IOCs`, The DFIR Report `DFIR-Report-Indicators`, and 360's IoC page.
- **The report's own IOC section**, parsed by a separate script and checked by hand (most of the remaining cases).

Keys are limited to indicators that appear in the report text. Every manual adjustment is noted at the top of the key file.

### Results so far
- **Recall:** 100% of in-text ground-truth indicators across all cases (PDF and HTML; English and Chinese; 10 to 62 pages; one report with no IOCs).
- **Screenshots:** 15/15 SHA256 hashes and 92/92 domains transcribed exactly from rendered tables.
- **Blind runs:** three independent agents using only `SKILL.md` found every ground-truth indicator. One ignored both planted injections (visible and hidden) and reported them.
- **Short versus long SKILL.md (round 10).** Twelve blind runs were made: six suite reports (3 PDF, 3 HTML), each reviewed once with the old 26.7 KB SKILL.md and once with the short version (`SKILL.md`, the reference guide and per-note guidance). Both variants had the same script and the same OCR files. Results, measured against each case's accepted reference output:

  | Measure | Long | Short |
  |---|---|---|
  | Recall on ground truth | 100% | 100% |
  | Agreement with the reference on what's kept (Jaccard) | 0.975 | 0.986 |
  | Agreement on confidence for shared indicators | 0.904 | 0.914 |
  | Extra or missing indicators against the reference | 3 / 1 | 1 / 2 |
  | Procedure errors (finalize failures, extra output files) | 0 | 0 |
  | Agent tokens, average per run | 98k | 97k |

  The short version kept quality while cutting the always-loaded instructions from 26.7 KB to about 11 KB. Token use barely changed, because the report and the candidates dominate the context. With one run per report the difference is within run-to-run noise, so the honest conclusion is "no loss", not "better". The runs' feedback (rules that conflicted, undocumented notes, uncovered cases) was folded into the guide and `guidance.json` afterwards.
- **Precision** isn't measured by vendor keys, which don't list every body-text indicator. It rests on reviewing the decisions and on the blind runs.

**Recommended next step:** have analysts hand-label two or three internal or partner reports and add them as cases.

---

## 10. Known limits

- **Formats:** PDF and HTML only. Images need transcription by Claude, which is accurate on clean images but not proven on poor scans.
- **Values the source alters** can't be repaired: masked characters (`f*ck.pdb`), brace shorthand (`apach.{txt,log}`), and values split over three or more lines of a narrow table column (such as WHOIS emails). The SKILL.md tells Claude to list these for the analyst.
- **Line-wrap repair** depends on the reviewer: the script flags likely wraps, and Claude adds the joined value, which the script verifies.
- **File names** are extracted automatically only for common extensions. Others (unknown extensions, extensionless Linux binaries) rely on reviewer additions.
- **Out of scope by design:** ports, user agents, mutexes, JA3/JA4, ASNs, crypto wallets, Telegram or GitHub handles, and report metadata such as TLP (planned for v2).
- **Parent domains are never derived** from FQDNs, URLs or emails, to avoid false positives on shared infrastructure. Since schema 2.2.0 a URL's *exact* host is offered as its own candidate (`derived_from_url`), because HTTPS traffic shows only the host to DNS, proxy and firewall logs. Claude excludes hosts of shared platforms (`drive.google.com`, `github.com`, compromised legitimate sites) as `shared_platform_host`; kept hosts carry `derived_from` in the output.

---

## 11. Change history

| Schema | Change |
|---|---|
| 1.0.0 | Initial output contract |
| 1.1.0 | Added `iocs.imphash`. Imphashes were previously typed as MD5, so they were matched against the wrong field. |
| 2.0.0 | Removed `iocs.imphash`: not actionable in this environment. Labelled imphashes are now excluded with reason `imphash` (breaking change for any consumer that read the field). |
| 2.1.0 | Registry keys may be written without a hive (`SOFTWARE\...`, `SYSTEM\...`) when the report gives them that way; match them under any hive. |
| 2.2.0 | Optional `derived_from` on IP, domain and FQDN entries: the host appears in the report only inside those URLs. It is the URL's exact host, never a parent domain, and never derived from emails. Consumers may hunt on derived hosts freely but should review before blocking. |

Extraction improvements made during testing (no schema change):
- PDF line-wrap and table-cell hints.
- YARA-constant, hash-of-a-name, key/parameter and URL-tail hints.
- IOC section start and end detection.
- Section-number and version-string rules.
- Unicode domains converted to punycode.
- Quoted registry keys and file names.
- Kernel-style and forward-slash paths.
- Footnote markers after file names.
- Relaxed reviewer additions for relative paths, extensionless names and any absolute Unix path.
- `#` allowed in file names (`Contract_02_21_Copy#909.one`); HTTP.sys wildcard URLs; detection-name hint; split-cell additions verified across an interleaved table line and through labels such as `URL://`.
- Compressed-sample extensions (`fast.ex_`, `system.dl_`), a leading `!` (`!start.cmd`), names with spaces on their own line in the IOC section (`ns v.2.exe`), section numbers followed by `C&C`, and reviewer additions of registry keys with spaces in the last segment (`...\Explorer\Shell Folders`).
- Round 7: extensionless names from HTML hash tables; split-hash, in-URL and certificate-thumbprint hints; host and underscore continuations; folders wrapped in the same column; IOC section end on two-column headings; PDF additions also verified against reading-order text; fragments with validation issues can be excluded.
- Round 8 (6 reports): HTML page chrome (navigation, related posts) skipped; hive-less registry keys; escaped string paths; `.dmp`, `.hlp`, `.db`; port, User-Agent and page header/footer notes; URL wrap hints no longer fire on closed or complete URLs; decisions can be keyed by `type|value`; additions are refanged and must stand alone (no derived domains); invalid URL additions dropped; warning when the IOC section lists almost nothing.
- Round 9 (6 reports: Citizen Lab ×2, Microsoft, Sophos, The DFIR Report ×2): PDF lookalike characters (CJK radicals, ligatures, fullwidth forms) normalised; kernel paths under `\Driver\`, `\FileSystem\`, `\Device\`; `\REGISTRY\MACHINE\...` keys; IPs encoded as one number in URL hosts; redacted hosts (`xxx.xxx`) excluded as `placeholder`; regular expressions no longer read as URLs; log and batch-line trailers trimmed (`.exe,file:`, `.exe&taskkill`); WMI namespaces not read as shares; `Imagename eq lsass.exe` filters; `.ico`, `.mf`; IOC section also ends at hunting-query and detection-guidance headings.
- Round 10: SKILL.md cut from 26.7 KB to about 11 KB (progressive disclosure: `references/review-guide.md`, and per-note guidance copied into `candidates.json`); blind A/B on 6 reports showed no loss.
- Round 11 (4 reports: Proofpoint, Trend Micro, Unit 42 ×2): URL hosts offered as candidates (`derived_from_url`, schema 2.2.0) with `shared_platform_host` for abused platforms; `reviewer_added` and exclusion `note` in the output; `in_table` on candidates; `*.domain` wildcards; glued URLs split and `hxxps` refanged inside parameters; `%2F` no longer yields fake domains; root-slash URLs merged; `%VAR%/` forward-slash paths; `==` in file names; `.lua`, `.key`, `.pid`, `.lock`, `.xpi`, `.crx`; HTML file-name columns limited to the same row and more header names (`Module Name`); certificate labels a table row above the hash; reason code `certificate_thumbprint`.
- Round 12 (4 new formats, each run twice blind: government advisory with a 3-column appendix, Check Point, a scanned PDF, a Japanese article): value boundaries are ASCII-only, so hosts and URLs glued to Japanese, Chinese or Korean text are found (and additions of them accepted); URLs stop at CJK text; `[.xyz]` defanging; CJK section headings; consecutive IOC appendices ("C2 servers", "hash values") form one section; page-chrome fallback no longer misfires on CJK pages; column-aware wrap detection for multi-column PDF tables (with page-footer and plain-word guards); mixed-case subdomains are not code; `derived_from` re-linked to the reviewer's joined URLs; names after a hash on a PDF IOC row (`5.t`); `.jpg`, `.png`, `.gif`. Repeatability on two runs per report: kept-set agreement 0.87–1.00, confidence agreement 0.975–1.00.
- Round 13 (6 reports, new sources: ESET HTML, Microsoft blog, CERT-UA in Ukrainian, Citizen Lab HTML, Positive Technologies 41-page PDF, NCC Group PDF): non-web URIs (`tcp://`, `udp://`, `tls://`, `quic://`, `socks5://`) extracted with their hosts; `port:N` on hosts taken from URLs; `(ws)://` defanging; IPv4 inside file names (`fresh-thinking_12.9.84.30_INSTALL.exe`) no longer splits the name; Ukrainian, Russian, French, German, Spanish, Portuguese, Italian and Polish IOC headings; a table header cell ("Detection") or a bare "MITRE" heading handled correctly as section ends; page-chrome probe keeps sidebar-styled article bodies; new warning `hash_column_cut_off` when a hash column ran off the printed page; `possibly_continues_after_space` on registry keys and escaped paths; `possibly_continues_before_space` on list lines and after "file"/"archive" words; additions with doubled backslashes accepted; spaces in URLs encoded as `%20`. Guidance for bundled legitimate components, hosts of placeholder URLs, public overlay-network peers, front-company domains, key material split into hash pieces, disclaimers on hash lists, and legitimate keys the malware modifies.
- Round 14 (strong validation: 4 unseen reports whose answer key is only the publisher's own IOC file, no hand edits; two blind runs each; extras judged by an independent reviewer). Shipped skill: Citizen Lab Kingdom 20/20, Poison Carp 18/24 (Cloudflare-hidden emails), ESET GhostRedirector and PlushDaemon 33/33 and 8/8 only through reviewer additions (script alone 16/33 and 4/8). Fixes: hashes, file names, hosts and paths printed over two lines of a PDF table cell are joined exactly (`joined_from_wrapped_cell`; hyphen breaks never join; the halves get `piece_of_joined_value`); Cloudflare-protected emails decoded offline; Android paths (`/data`, `/system`, `/sdcard`); app IDs noted `possibly_package_name`; new warning `iocs_published_separately`. After the fixes the script alone finds every key value in all four reports, and the joins recovered values in 11 older cases (CISA, Citizen Lab, 360, ESET, Recorded Future, Trend Micro, Winnti).

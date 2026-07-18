# CloudAudit anomaly recovery contract

This guide connects the incident-recovery request to the precise machine contract in `report_spec.json`. The JSON specification remains authoritative whenever this guide summarizes a rule.

## Operator commands

Create `/app/log_audit.py` with these commands:

- `diagnose --dossier PATH --report PATH`
- `repair --output-dir PATH`

An explicit `diagnose` call is stateless. It always writes a diagnosed report, regardless of the current workflow or existing repair artifacts. A repair reinstalls the corrected workflow, runs it in the requested directory, reruns it to prove idempotency, and leaves a repaired diagnosis at the output location.

Use `/app/incident/export_dossier.md` and the frozen bytes at `/app/workflow/.export_report.original` as audit evidence. Never modify the frozen file.

## Diagnostic evidence

The diagnosis covers these six deployment defects:

- `wrong_source_field`
- `risk_threshold_filter`
- `recency_order`
- `risk_class_normalization`
- `dedupe_event`
- `benign_filter`

Each finding contains `id`, `severity`, `description`, `resolution`, and an `evidence` object containing `dossier_quote`, `pipeline_evidence`, and `repair_action`. Dossier quotations are verbatim and at least 30 characters. Pipeline evidence and repair actions are at least 10 characters. **`pipeline_evidence` must be a character-for-character verbatim substring of the frozen original workflow source at `/app/workflow/.export_report.original` — copy an exact run of source text (preserving whitespace, punctuation and case exactly as it appears in the file); a paraphrase, a reformatted line, or a whitespace-normalized version will not match.** **Every one of the three evidence strings must additionally contain a set of mandatory terms that differ per issue id. Those terms are enumerated in `/app/docs/report_spec.json` at the exact path `diagnosis_report.issues_found_item.evidence.required_terms_by_issue`, keyed by issue id and then by evidence field. Read that object directly — for example with `python3 -c 'import json;print(json.dumps(json.load(open("/app/docs/report_spec.json"))["diagnosis_report"]["issues_found_item"]["evidence"]["required_terms_by_issue"], indent=2))'` — rather than paging the file, which is large enough that terminal output may truncate before you reach this section.** Matching is a plain case-sensitive substring test: the term must appear with exactly the capitalization, spacing and punctuation listed. Writing `Normalize severity` where the spec lists `normalize severity`, or `timestamp` where it lists `timestamp source`, fails the check even though the prose reads correctly. This applies to all three evidence fields, including terms assembled into a repair action.

A diagnosed report contains only `pipeline_status`, `issues_found`, and `input_stats`, with status `diagnosed`. `input_stats` carries exactly the keys `alert_count`, `unique_alert_ids`, and `asset_groups` — no aliases. It does not contain `verified_summary` or `output_paths`. A repaired report has status `repaired`, embeds the generated summary, and uses the semantic path keys `summary_json`, `flagged_jsonl`, and `service_matrix_json`.

## Anomaly processing

The workflow canonicalizes alerts and deterministically deduplicates them by `alert_id`. Muted or actively overridden candidates do not enter the triage queue. Override windows are normalized and compacted before overlap and pressure calculations.

Related alerts form transitive chains. Chains then participate in a directed reach graph whose strongest path is propagated in deterministic order. Chain reach affects final row ordering, anomaly digests, and summary checksums. `report_spec.json` defines the schemas, checksum serialization, and digest payloads; the normalization rules, tie-break cascade, interval boundaries, edge rules, and equations themselves were settled during the CloudAudit review and are recorded as #CloudAudit-ticketed decision notes in the incident dossier — reconcile them there, and note the February triage proposals were partly reversed later.

## Repair audit and artifacts

Every repair reads the pre-repair SHA-256 from the frozen bytes before replacing the active workflow. `repair_audit.json` contains `patched_workflow`, `processing_steps`, `removed_tokens`, `pre_repair`, and `post_repair`. Copy `processing_steps` from the JSON specification without paraphrasing it.

`removed_tokens` maps each forbidden token string to a boolean. The removed-token map uses the exact source literals `event["observed_at"]` and `severity == "critical"`. The post-repair section records integer `escalated_count` and `rerun_escalated_count`.

The requested output directory contains exactly:

- `summary.json`
- `service_matrix.json`
- `flagged.jsonl`
- `diagnosis.json`
- `repair_audit.json`

Write `flagged.jsonl` as compact JSON Lines. All schemas, sort keys, field domains, checksums, and digest payloads are defined in `/app/docs/report_spec.json`.

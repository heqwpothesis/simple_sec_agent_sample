# Source–Sink Pipeline

Improved static pipeline tailored for DVWA (PHP) and NodeGoat (Node/Express). It scans real project folders, identifies untrusted sources, follows simple intra-file assignments, and highlights dangerous sinks with evidence numbers. Results are written to JSON so you can hand them straight to an LLM for deeper explanation.

## Layout
- `run_pipeline.py` – CLI entry point (Python 3.10+).
- `config.yaml` – sample configuration that targets DVWA SQLi/XSS folders and NodeGoat routes.
- `source_sink_pipeline/` – package containing analyzers and helpers.
  - `analyzers/php.py` – PHP taint propagation using superglobal detection, assignment tracking, sink matching.
  - `analyzers/javascript.py` – Node/Express taint tracking (req.* sources, eval/DB/response sinks).
  - `utils.py` / `pipeline.py` – config loading, directory walking, orchestration.

## Run it
```bash
python3 run_pipeline.py --config config.yaml --json > findings.json
```
- The bundled config uses paths relative to this folder and will inspect `../DVWA/...` and `../NodeGoat/app/...`.
- Pass `--output output.json` to save to a custom location.
- Drop `--json` if you only care about the summary line; the script always writes to the configured file.

## Example output snippet
```json
[
  {
    "file": ".../DVWA/vulnerabilities/sqli/source/low.php",
    "line": 11,
    "sources": ["$id"],
    "sink": "$result = mysqli_query(...)",
    "flow": "$id -> mysqli_query(...)",
    "evidence": {"$id->query": 31}
  }
]
```
Use the `evidence` map to jump from sink to the line where the tainted variable was composed.

## Extending rules
- Update `source_sink_pipeline/analyzers/php.py` to add new sanitizers or sinks (e.g., file includes, command execs).
- Update `source_sink_pipeline/analyzers/javascript.py` for additional Express middleware patterns or sanitization helpers.

This pipeline is deterministic and fast (no Node dependencies). It finds the classic DVWA SQL injection flow and NodeGoat’s `eval` sinks out of the box, making it a solid pre-processing step before your LLM walkthrough.

## Optional: prepare LLM context
```bash
# after generating findings.json
python3 context_generation/build_context.py --findings findings.json --output context_payloads.json
```
This tries to use `tree_sitter_languages` to extract the containing function/class for each finding. If tree-sitter is unavailable it falls back to brace-based slicing. The result is a JSON payload with `code`, `start_line`, `sink_line`, `flow`, etc. ready for prompting an LLM.

## Render prompts
```bash
python3 prompt_generation/generate_prompts.py --context context_payloads.json --output prompts.json
```
This produces detection/remediation prompt text for every finding so you can feed them directly to your LLM client.

## Call the LLM (optional)
```bash
python3 prompt_generation/query_llm.py --prompts-file prompts.json --index 0 --type detection
```
Requires environment variable `ARK_API_KEY` and the `openai` Python package (install with `pip install openai`). Add `--stream` for streaming responses or `--type remediation` to send the fix prompt.

# RogueCheck

Minimal, extensible scanner for "rogue code" patterns in AI-generated snippets.

## Quickstart
```bash
python -m roguecheck scan --path . --format md --fail-on high
```

### Options

* `--policy policy.yaml` — organization policy knobs.
* `--allowlists allowlists.yaml` — domain and path allowlists.
* `--format md|json|sarif` — output type.
* `--fail-on low|medium|high|critical` — exit non-zero at/above threshold.

## Extending

Drop a `.py` file in `roguecheck/plugins/` that exposes `get_rules() -> list[callable]`.
Each rule is `fn(path: str, text: str, policy) -> Iterable[Finding]`.

For richer Python checks, switch `ast` to `libcst` or `astroid` without changing the scanner contract.

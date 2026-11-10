# Eval results

This directory holds **committed eval-harness output**. Files here are produced
by an actual run of the harness, never edited by hand:

```
# offline / reference PDP
python -m eval --out eval/results/latest.json

# authoritative OPA-backed run (maintainer machine / CI, OPA 1.22.3)
python -m eval --out eval/results/latest-opa.json --opa
```

Each results file records a **timestamp + git SHA** and the per-case outcomes,
so any number can be traced to a specific run.

**README / report numbers may only be cited from a committed results file in
this directory.** Until an OPA-backed run is committed, the README states
"planned / to be measured" and quotes no figures.

The `.json` results files are intentionally not pre-populated; add them from a
real run.

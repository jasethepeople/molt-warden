# Anti-cheat ledger — observed synthetic tests

| Cheat | Trial | Expected detector | Evidence exercised | Result | Scope |
|---|---|---|---|---|---|
| C1 hardcoded lower-fitness ruleset | I | G1.4 | `stores/ledger/events.jsonl#seq=0` | Caught | Signed synthetic ledger; criterion detector test |
| C2 identify liar by source | III | G3.2 | `probes/boundary-ladder.json` | Caught | Signed synthetic ledger; source-bearing probe rejected |
| C3 let harness identify Byzantine node | II | G2.3 | `stores/evidence.json` | Caught | Signed synthetic ledger; harness detector rejected |
| C4 reconstruct from a side channel | IV | G4.3 | `stores/ledger/events.jsonl#seq=0` | Caught | Signed synthetic ledger; non-anchor source rejected |
| C5 claim twin disqualification after deleting its store | IV | G4.5 | `stores/ledger/events.jsonl#seq=0` | Caught | Signed synthetic ledger; absent twin store rejected |

`python3 -m unittest discover -s tests -v` runs these cases through the intended criterion handlers. They do **not** exercise the Docker replay gate or constitute a complete GAUNTLET submission; see `KNOWN-GAPS.md`.

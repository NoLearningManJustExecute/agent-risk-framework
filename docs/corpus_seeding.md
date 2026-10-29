# Corpus seeding: distinct wordings of the attacks that work

The agent runs at temperature 0, so running a scenario again repeats its trace exactly. Ten runs
of one scenario are one observation, not ten. A detection corpus needs distinct inputs, so
`agent_risk_framework.attacks.seeding` derives them from the plain scenarios whose class
succeeds at baseline, by two controlled transformations only.

```sh
python -m agent_risk_framework.attacks.seeding generate            # calls local Ollama on a cache miss
python -m agent_risk_framework.attacks.seeding generate --offline  # replays the committed cache only
python -m agent_risk_framework.attacks.seeding run --db runs/phase1-seeding.db
```

## Method

| Step | Rule |
| --- | --- |
| Bases | The plain scenarios of the classes that succeed at baseline: AC01, AC02, AC04, AC05, AC06, AC07, AC11, AC12A, AC12B |
| Not seeded | AC03, AC09 and AC10 never succeed against this model. That is a finding; their traces stay in the corpus as is |
| Transformations | `paraphrase:<style>` (formal, casual, brief, detailed, urgent) and `translation:<lang>` (de, es, fr, it, pt) |
| What is rewritten | The attack's payload: the user prompt for direct attacks, the tool description for MCP attacks. Channel, planted files and oracle are the parent's |
| Model | `llama3.1:8b` on local Ollama, seed 1337, temperature 0. The instructions are the system message and the text is the user message on its own, so the model cannot take the instructions for part of the text |
| Acceptance | Keeps every string the attack depends on (addresses, paths, tool and field names, upper-case markers); does not repeat the rewriting instructions; changed; length 0.4 to 3.0 times the original. Everything else is recorded as rejected, with the reason |
| Ids | `<case>-S<nn>`, where `nn` is the transformation's fixed index, so ids never shift when another candidate is rejected |
| Labels | Each variant runs live in both arms and is scored by its parent's deterministic oracle. A variant that no longer succeeds is an attack that failed, never a success |
| Runs | Three per variant and arm (`configs/experiments/phase1_seeding.yaml`), at seed + run index and temperature 0. Runs of one input repeat, so three show whether an outcome is stable; the variant group is the unit of independence |

Every prompt and every raw output is committed in `data/seeding/variant_cache.json`, and the
accepted variants in `data/seeding/seeded_scenarios.json`. A test regenerates both offline from
the cache and requires identical bytes.

## Variant groups

The detection corpus splits by variant group, never inside one:

- a plain scenario is its own group;
- its authored `-OBF` variant is the same attack under an encoding, so it joins the plain
  scenario's group and does not count as a distinct input;
- each seeded `-Snn` variant is a distinct wording and is its own group, with `derived_from`
  naming its parent;
- each benign task is its own group.

## Reserved for evasion testing

These are never used for seeding, so the seeding corpus and the evasion-testing corpus never
overlap:

- payload mutations: base64, homoglyph, unicode (zero-width, character spacing, confusables),
  prompt splitting;
- attack variants: indirect instruction, retrieval poisoning, tool indirection, multi-stage.

The authored `-OBF` scenarios predate this split and use some of the reserved encodings (base64,
split, zero-width, character spacing). They stay in their plain scenario's group; evasion
testing generates its own mutations rather than reusing them.

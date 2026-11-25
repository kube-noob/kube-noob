# Corpus, training and the reward

## Build the local corpus

```bash
kube-noob corpus build --online
kube-noob corpus history --online
kube-noob corpus jira --online --projects ROX --max-requests 1200
kube-noob corpus verify
kube-noob corpus stats
```

- Git sources are sparse-cloned with commit provenance and an SPDX license per record (`src/kube_noob/sources/registry.py`).
- The Jira pull is jittered and rate-limited, keeps no identities, and scrubs emails and account ids. For non-public
  projects set `JIRA_EMAIL` and `JIRA_API_TOKEN` (sent over HTTPS only).
- Copyleft, non-commercial, unlicensed and Jira content is `redistributable: false`: usable for local retrieval and
  private evaluation, excluded from exports unless you pass `--include-restricted`.
- Air-gapped clusters: `kube-noob corpus import corpus.tgz` (names and checksums are verified before import).
- The `corpus-refresh` workflow rebuilds everything weekly in GitHub Actions.

## Export datasets and grade

```bash
kube-noob train export --out dataset/
kube-noob train grade --task bench-qa-rwx-gp3 -f answer.md
kube-noob train bench --out report.json
```

`train export` writes `sft.jsonl` (chat format) and `grpo_prompts.jsonl`. The held-out benchmark
(`src/kube_noob/data/evals/tasks.yaml`) is never exported. Exports contain no LLM-generated labels.

## The reward (enforcer and credit system)

```
reward = 0.70 * task + 0.20 * credit * task + 0.10 * format - penalties
```

- **task**: manifest answers are graded by the audit engine plus field assertions that encode the task's intent; a
  failed assertion or forbidden rule caps the task score at 0.4. QA answers need affirmative claims (negated mentions do
  not count), any known-wrong claim scores 0, and answers under `minWords` are scaled down.
- **credit**: share of `[kn:...]` citations that exist and support the answer (task-declared docs, top hits for the
  prompt, or lexical support of the citing sentence). Credit only counts in proportion to correctness.
- **penalties**: fabricated citations, refusals, runaway length.

Use it with TRL: `GRPOTrainer(reward_funcs=[kube_noob.evals.reward.trl_reward], ...)` and a `task_id` dataset column.
The eval-only LLM judge (`judge.provider`) is for spot checks; its output is never exported as a label.

## Serve a fine-tuned model

Point the agent at any OpenAI-compatible endpoint (vLLM, Ollama, llama.cpp, OpenShift AI model serving):

```yaml
llm:
  provider: openai-compatible
  baseUrl: http://kube-noob-model.ai.svc:8000/v1
  model: kube-noob-8b
  apiKeyEnv: VLLM_API_KEY
```

`apiKeyEnv` is the only variable the model client reads for `openai-compatible`, and there is no fallback: without it
the request carries no `Authorization` header. `ANTHROPIC_API_KEY` is the default for `llm.provider: anthropic` alone,
so pointing `baseUrl` at a gateway cannot quietly hand that key to a third party.

Then compare it with a frontier baseline: install the SDK with `pipx install 'kube-noob[ask]'`, set
`llm.provider: anthropic` and `ANTHROPIC_API_KEY`, and run `kube-noob train bench --out report.json`. No model is
configured by default.

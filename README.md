# workflow-proof-sandbox

A disposable, synthetic repository for testing how CI keeps credentials away
from untrusted code, and how an implementation agent and a review agent stay
separate. The code is a tiny integer arithmetic library with tests. Nothing here
is real data, and the repository is deleted when the tests are done.

Repository: `sawyer-1323/workflow-proof-sandbox`

## Contents
| Path | Purpose |
|---|---|
| `src/arith.js` | Integer helpers: add, subtract, multiply, floor division, half-even rounding |
| `test/` | Unit tests, golden tests, and validator tests (`npm test`, no dependencies) |
| `spec/arith-spec.md` | The specification table: the independent oracle |
| `test/golden/PROTECTED.sha256` | Recorded hashes of the protected baselines |
| `toolchain/` | Sample .NET and pgTAP suites for the toolchain check |
| `scripts/` | Sandbox, proxy, artifact validator, golden and policy guards, static key check, run budget and probes |
| `scripts/audit/` | Read-only tools the owner runs locally: the run audit (`run-audit.js`) and the secret-boundary evidence report (`ds3-evidence.js`) |
| `AGENTS.md`, `CLAUDE.md`, `docs/guides/review.md` | Agent and reviewer policy, always read from `main` |

## Workflows (read-only phase)
| Workflow | Jobs | Credentials |
|---|---|---|
| `ci.yml` | `test`, `key-references`, `workflow-lint` on `pull_request` | `GITHUB_TOKEN` with `contents: read` only |
| `review.yml` | `golden-guard`; `policy-guard`; `review-agent`; `review-publish` (`pull_request_target`, runs the `main` copy) | Agent job: the model key reaches only the model proxy (live stage only; a synthetic dummy and an offline proxy in the dummy stage); read-only `GITHUB_TOKEN` for checkout and the run budget. Publish job (live stage only): the artifact decryption key; no App token |
| `probe.yml` | `probe-agent`; `probe-publish` (`workflow_dispatch` on `main`, owner only) | Agent job: isolation, network, request-path, hostile-output and output-trace probes; the model key only in `probe-requests`, live stage. Publish job (live stage only): the review App key (read-only token, minted only for token tests) and the artifact decryption key |

Agent jobs run the agent as an unprivileged `agent` user with no sudo and a
placeholder model key. Its only network destination is a local model proxy,
running as a separate `modelproxy` user, which holds the real key and allows
only listed endpoints, one model, and capped requests to the model API. Agent
output leaves the job only as an encrypted artifact, kept for one day, which the
publish job decrypts and validates as data and never executes, uploads or logs.
All four environments allow deployments from `main` only. There are no
repository-level secrets.

The artifact public key is `.github/proof/artifact-public.pem`, added at setup.

## Running locally
```sh
npm test
node scripts/check-key-references.js .github/workflows
```

## Protected baselines
`spec/`, `test/golden/` and `test/golden.test.js` are protected. The
`golden-guard` job in `review.yml` fails any pull request that changes them or
their recorded hashes.

## License
MIT. Synthetic test content.

# github-core-clone-01

[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/competitions/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/sheeran154/makefun-github-core-clone-01/rank.svg)](https://make.fun/competitions/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/sheeran154/makefun-github-core-clone-01/reward.svg)](https://make.fun/competitions/github-core-clone-01)

A standalone GitHub-compatible git forge in a single Node.js process — written
from scratch with the standard library only (`node:http`, `node:crypto`,
`node:zlib`). No npm packages, no git binary, no network beyond the trial
environment, no UI. One `main.ts` serves all four surfaces from one
in-memory store:

| Surface | What it speaks |
| --- | --- |
| Git smart HTTP `/{owner}/{repo}.git` | upload-pack protocol v2 (advertise, ls-refs, fetch) with a v0 fallback, receive-pack v0 (fast-forward only, per-ref report) |
| REST v3 `/api/v3` | repos, branches, commits, contents, labels, issues, pull requests (incl. squash merge), pagination via `Link` headers |
| GraphQL v4 `/api/graphql` | repository / issue / pull-request queries, `__type` introspection, mutations, cursor pagination, batched documents |
| MCP `/mcp` | JSON-RPC 2.0 Streamable HTTP: `server/discover` (2026-07-28) and the legacy `initialize` handshake, `tools/list`, `tools/call` |

## How it works

- **Git objects, from first principles.** Loose-object store with SHA-1 ids
  and zlib compression; packfile parsing (v2/v3, `OBJ_OFS_DELTA` /
  `OBJ_REF_DELTA` resolution) and packfile generation (plain objects, SHA-1
  trailer); pkt-line framing for advertisements, ls-refs, fetch and push.
- **Fetch is depth-aware.** Full clones, incremental fetches (only objects
  the client does not hold — a have only holds history down to the shallow
  boundary beneath it), shallow clones (`deepen`, `deepen-relative`,
  `deepen-since`, `deepen-not`), tag wants (annotated tags are peeled for
  depth and negotiation), and multi-round negotiation (`ACK` / `ready`).
  When the client sends `done`, the v2 fetch response carries no
  `acknowledgments` section — exactly what real git expects.
- **One store, four views.** REST, GraphQL and MCP all read and write the
  same repos, issues and pull requests, so an issue created over MCP shows
  up over REST and GraphQL with the same ids.
- **Deterministic state.** No wall clock and no unseeded randomness in stored
  state: every id and timestamp comes from deterministic counters, so a
  replay of the same requests leaves a byte-identical state export.

## Running it

```sh
MAKEFUN_SHOP_TOKEN=<token> node --experimental-strip-types main.ts
```

The server binds an ephemeral port (port 0), registers it with
`$MAKEFUN_ENV_URL/register`, serves until `$MAKEFUN_ENV_URL/done` reports
`{"done": true}`, then exits 0. Without `MAKEFUN_ENV_URL` it just listens
on `127.0.0.1` and prints its port — handy for local testing with the git
CLI and curl. `GET /healthz` answers `{"ok": true}`.

## Verified

Practice trials via the kit's own grader
(`node cli/makefun.mjs grade-local --kit . --bot . --driver process --worktree --instances 3`):

| Trial | Feature | Agent (MCP) | Perf | Total |
| --- | --- | --- | --- | --- |
| 0 | 600 / 600 | 200 / 200 | 179 / 200 | 979 |
| 1 | 600 / 600 | 200 / 200 | 177 / 200 | 977 |
| 2 | 600 / 600 | 200 / 200 | 155 / 200 | 955 |
| **mean** | **600** | **200** | **170.3** | **970.3** |

**120 / 120 conformance checks pass on every trial**, and the replay check
reproduces the state export byte for byte. Also verified by hand against
the real git CLI: full and shallow clones, deepen to full history,
fast-forward and non-fast-forward pushes, mixed pushes, annotated tags,
incremental fetch, and protocol-v0 clones.

## Layout

- `main.ts` — the whole forge (git + REST + GraphQL + MCP + lifecycle).
- `LICENSE` — MIT.

---

*Built for the [make.fun](https://make.fun/competitions/github-core-clone-01)
github-core-clone-01 bounty. Referral: `nvhyrpj1`*

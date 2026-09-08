# Linnix as an MCP server

`linnix-cli mcp serve` exposes what cognitod already knows about a running Linux
host to any MCP client — Claude Code, Codex, an SRE agent — over stdio.

The premise is that reasoning is not the scarce thing any more. A frontier
model can already form a good hypothesis about why a pod got slow. What it
cannot do is look at the machine. Linnix's job is therefore to supply *facts*
about the running system in a form a model can consume, and to leave the
reasoning to the model.

That framing has a consequence worth stating up front, because it constrains
every tool below: **Linnix reports contention attribution, not proven
causality.** The daemon can say that two workloads contended over a resource
while a victim stalled, and how much of the stall each neighbour accounts for.
It cannot say that removing the neighbour would have prevented the stall.
Confirming that means changing something and watching the stall fall — see
milestone 3.

## Why this lives in `linnix-cli`

The MCP server is a subcommand of the existing CLI rather than a new crate.
Everything it needs already exists there:

- `investigate.rs::summarise()` collapses raw `/attribution` rows into one
  ranked entry per offender, and already handles the trap that `stall_us`
  repeats across every offender row of one window and so must not be summed.
- `explain.rs::IncidentView` decodes a stored incident, including the
  three-state `investigation_rendered` field and the terminal-control
  sanitisation that any untrusted `comm` string needs.
- `http.rs::client()` carries `LINNIX_API_TOKEN` as a bearer token, which is
  what a cognitod started with an API token requires on every TCP route.

A separate crate would have meant reimplementing all three. The MCP layer is
therefore a *presentation* of the CLI's existing analysis, not a second
analysis that could drift from it.

## The context compiler

Every tool takes a `detail` argument. It is the whole idea of the context
compiler in one parameter: an agent should be able to ask a cheap question
first and pay for evidence only when it decides the answer matters.

| `detail`   | Roughly | Contains |
|------------|---------|----------|
| `summary`  | ~100 tokens | One or two sentences: the conclusion and the single strongest number behind it. |
| `evidence` | ~500 tokens | The compiled facts — ranked offenders, shares, windows, peak CPU share, dominant signal. The default. |
| `raw`      | unbounded | The daemon's own JSON, **verbatim**, plus a permalink that re-runs the exact query. |

`raw` is passed through undecoded rather than round-tripped through this
crate's structs. That is not an implementation detail: a decode-and-re-encode
would silently drop every field cognitod sends that the CLI does not happen to
declare, and the one tier whose entire purpose is to be quotable would be
handing back a filtered view while calling itself raw.

The tiers are enforced by a test that loops over every tool, because a tool
whose `summary` quietly equals its `evidence` fails silently: a caller that
obeys the instruction to start cheap pays full price and never learns why.

`summary` is what an agent should call when it is triaging and does not yet
know whether this host is even relevant. `raw` is what it should call when it
has decided to write up a finding and wants something citable.

There is deliberately **no `confidence` field**. A float would be read by a
consuming model as calibrated, and nothing here calibrates it. What the tools
return instead is the evidence a reader would need to form their own view:
which offenders, what share of the attributed stall, over how many detection
windows, and what the daemon classified the dominant signal as.

## Tools

All tools return a structured error when cognitod is unreachable rather than
failing the call, since a developer box with no daemon running is the most
common first contact an agent will have with this server.

| Tool | Backing endpoint | Answers |
|------|------------------|---------|
| `linnix_system_health` | `/status`, `/system` | Is this host under pressure right now, and is the daemon healthy? |
| `linnix_investigate_contention` | `/attribution` | Which workloads contended with this pod while it stalled, and on what evidence? |
| `linnix_explain_process` | `/processes/{pid}`, `/graph/{pid}` | What is this PID, what started it, and what did it start? |
| `linnix_recent_incidents` | `/incidents` | What has the daemon flagged recently? |
| `linnix_explain_incident` | `/incidents/{id}` | What was concluded about one incident, and on what evidence? |

## Running it

```console
$ linnix-cli mcp serve --url http://127.0.0.1:3000
```

The server speaks MCP over stdio and logs to stderr, because stdout is the
transport. Registering it with Claude Code:

```console
$ claude mcp add linnix -- linnix-cli mcp serve --url http://127.0.0.1:3000
```

If cognitod requires a token, set `LINNIX_API_TOKEN` in the environment the
MCP client launches the server with.

## Where this goes next

This document covers milestone 1. The two that follow are sketched here so the
shape of milestone 1 can be judged against them, but neither is started.

**Milestone 2 — temporal causal graph.** Today `/attribution` answers "who
contended with this pod" over a flat window. The graph would make the
edges explicit and traversable: deployment → pod → container → process →
contention → victim → request, with time on every edge. That turns "what is
happening" into "what changed", which is the question an operator actually
asks and the one a flat metric store answers worst.

**Milestone 3 — the experiment loop.** The caveat at the top of this document
is a gap Linnix is unusually well placed to close: it already has an
enforcement path with an explicit, opt-in safety model. A guarded experiment —
cap the suspected offender's CPU for fifteen seconds, watch whether the
victim's stall falls — converts an attribution into a tested claim. That is
the step no amount of model reasoning can substitute for, and it is why the
`confidence` field is omitted now rather than guessed at: when there is a
number worth reporting, it should come from an observation.

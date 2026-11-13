# ADR 0007 — An error in the shield lets the request pass

- Status: accepted (2026-10-03; [0031](../proposals/0031-robust-core-plugins.md) steps A.2 and A.3)

## Context

`Shield::protect()` and `Settings::load()` have no `try/catch`. A rule file
that fails to compile after a deploy, or a throwable in a rule or a store, is a
fatal error in `auto_prepend_file`: every visitor gets a 500. `AGENTS.md` says
"fail safe: unsure → let the request through"; the code did not.

## Decision

- Any `\Throwable` inside the decision path (`protect()`, `protectFile()`,
  `requirePass()`, `consume()`, `widget()`, the output-buffer callback) ends
  with `Decision::allowUncached('shield error')`: the application runs, no
  cache keeps the answer, `error_log` gets one line a minute.
- A rule file that fails to compile keeps the **last good** compiled settings
  (a `.failed` marker stops recompiling until a source changes). Without any
  compiled settings the shield runs as `mode off` and logs.
- A truncated compiled file is deleted and rebuilt on the next request.
- `request-shield check` stays strict: the CLI is where errors are seen.
- A long-running server (one PHP process for many requests) cannot let a
  script call `exit()` and throws an exception of its own instead. Named with
  `Shield::passThrough()`, such exceptions pass `protect()`, `requirePass()`
  and `consume()` unchanged: they end a request the shield answered, they are
  no shield error (2026-11-12).

## Consequences

- A broken deploy degrades protection instead of taking the site down; the log
  says so once a minute.
- Every guarantee has a test in `tests/RobustnessTest.php` that fails without
  the catch.

# AGENTS.md

Instructions for AI coding agents working on this repository. Humans: see
`CONTRIBUTING.md`, which says the same in more words.

## What this is

`se7enxweb/request-shield` (7x distribution of cjw-network/request-shield): a dependency-free PHP (≥ 8.0) library that runs
before the application (`auto_prepend_file` or the first line of a front
controller) and decides whether a request reaches it and may be cached.
Entry points: `src/Shield.php` (`protect()`, `protectFile()`), `bootstrap.php`.
Settings: `src/Config.php` (defaults) → `src/Settings.php` (checked, compiled).

**Ongoing restructuring:** the plan is `docs/proposals/0031-robust-core-plugins.md`;
the current state and the next step are in `docs/proposals/0031-steps.md`
(it has a resume prompt). Finish a step, tick it there, commit both together.

## Rules

- **Correct and fast, always.** Every change: tests (`php tests/run.php`), a
  benchmark before and after (`php -d apc.enable_cli=1 -d opcache.enable_cli=1
  -d opcache.file_update_protection=0 bench/overhead.php` -- without the last
  flag OPcache re-reads the freshly compiled settings for 2 s and the "setup"
  lines show milliseconds), numbers in the pull request. Nothing a feature needs may
  run on the passing path when the feature is not used. A `stat()` costs more
  than most checks — avoid them on the request path.
- **Tests:** unit tests plus an end-to-end case for request-path changes; the
  challenge page's script is tested in Node (`tests/ChallengeJsTest.php`).
  Confirm a new test fails without the change. Use `skip()` when a test cannot
  run here; never let it pass silently.
- **Compatibility:** PHP 8.0 syntax and functions only (RHEL 9 baseline): no
  `readonly` (mark public properties `@readonly`; PHPStan enforces it), no
  enums, no `never`, no string-key unpacking, no `array_is_list()`, no `xxh*`
  hashes — or guard them with `PHP_VERSION_ID`; no runtime
  dependencies; `composer phpstan` (level max) and `composer taint` stay clean.
- **Fail safe:** unsure → let the request through; refuse only clear cases.
- **Docs in the same change:** `docs/features/`, `docs/proposals/` (new ideas,
  status Draft), `docs/adr/` (decisions), `CHANGELOG.md` (*Unreleased*).
- **Security:** never log or expose the secret; escape everything a page
  embeds; compare MACs with `hash_equals()`.
- **Commits:** one change each; "Added:/Fixed:/Updated: <what the code does now>".

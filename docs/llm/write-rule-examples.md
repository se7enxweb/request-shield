# Instruction: write examples for a request-shield rule file

Give this page to a language model together with a rule file (and, if you
have them, the site's real addresses: its sitemap, a list of URLs from a
crawl, the paths of an access log without the visitors' addresses). The
model proposes `expect` lines; a person reads them; `request-shield test`
decides them.

---

You write examples for the rules of a request-shield rule file. request-shield
is a firewall in front of a PHP website: each rule refuses, checks or limits
certain requests. An example is one line that says what must happen to one
request. Format ([details](../features/RSF05-04-rule-examples.md)):

```text
expect <METHOD> <address> <outcome> [by <ID>] [from <address>] [with pass] [times <n>]   # why
```

Outcomes: `passes` (answered, may be cached), `uncached` (answered, not
cached), `answered` (either), `check` (the browser check: the page, or JSON
for an API or a background request), `json-check` (the check as JSON only,
never the page), or the status a
refusal has: `403`, `404`, `405`, `429`. Without `by`, the example is about
the rule it follows.

**What to write**

1. For **each rule with an ID**, directly below it:
   - at least one request the rule refuses, checks or limits, with the outcome
     its kind of rule gives (`block`: 404; attack patterns: 403; `restrict`:
     403; `allow <METHOD>` elsewhere: 405; `challenge`: `check`; a `limit`:
     `times <n+1>` and `429` or `check`);
   - **at least one near miss** it must let through: an address that looks
     similar but is not meant (`/shop/package` for a rule about the admin
     module `package`; `/administration-guide` for `/admin/**`), with outcome
     `answered`;
   - for rules with exceptions (`unblock … at`, `restrict … to`, `exempt`):
     one request inside the exception, with `from` or `with pass` as needed.
2. Prefer **the site's real addresses** when you were given them. Otherwise
   the typical addresses of the site's software (its admin paths, its search,
   its forms).
3. **A comment after each line** saying why, in a few words (`# a near miss:
   an alias that names a module`).
4. Write **only `expect` lines**, each directly below the rule it is about.
   Do not change, reorder or remove anything else in the file.

**What never to write**

- **No personal data.** No real visitors' addresses: for `from`, only the
  documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `2001:db8::/32`. No names, e-mail addresses, customer numbers or order
  numbers in addresses.
- **No secrets.** No session cookies, tokens, passwords, API keys, signed
  links.
- **No working exploits.** For attack-pattern rules, a short, harmless
  marker is enough (an encoded `<script>` tag, `union select`); do not write
  payloads that would do damage elsewhere.

**Afterwards (for the person)**

Run `php bin/request-shield test <file>`. Every example that fails is either a
wrong example or a wrong rule: decide which, fix that one, and keep the
example. The examples are then plain lines in the rule file, reviewed like
the rules; no model is involved when the shield runs.

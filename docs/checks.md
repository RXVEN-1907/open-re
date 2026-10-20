# Web security checks

`openre-scan` ships 18 built-in checks (`crates/openre-scan/src/checks.rs`). Each check is one HTTP analysis pass against the target; it returns zero or more `Finding`s. Checks are selected by scan profile and can be filtered per run with `--checks` / `--exclude` (comma-separated check names).

## Profile membership

| Check name | Profile | Detects |
| --- | --- | --- |
| `http-headers` | quick, standard, full | `Server` and `X-Powered-By` header disclosure |
| `security-headers` | quick, standard, full | Missing `X-Frame-Options`, `X-Content-Type-Options`, HSTS, CSP, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP |
| `cookie-security` | quick, standard, full | Cookies missing `Secure` (on HTTPS), `HttpOnly`, or `SameSite` |
| `tls-certificate` | quick, standard, full | Plain HTTP targets, HTTPS connection failures |
| `info-disclosure` | quick, standard, full | Debug headers (`X-Debug-Token`, `X-Drupal-Cache`, `X-Varnish`, `Via`, `X-Cache`), `Server` version strings |
| `tech-fingerprint` | quick, standard, full | Server/framework signatures in headers (PHP, ASP.NET, Apache, nginx, IIS, WordPress, Drupal) and body (WordPress, Drupal, Joomla, React, Vue, Angular, jQuery, Bootstrap) |
| `csp` | standard, full | Missing CSP; `unsafe-inline`, `unsafe-eval`, wildcard `*` directives |
| `cors` | standard, full | `Access-Control-Allow-Origin: *`, credentials combined with wildcard origin |
| `robots-txt` | standard, full | Accessible `/robots.txt` and non-trivial `Disallow:` entries |
| `sitemap` | standard, full | Accessible `/sitemap.xml` |
| `dir-listing` | standard, full | Directory-index page markers in the response body |
| `sensitive-files` | standard, full | 21 probed paths (`.git/`, `.env`, `config.php`, `wp-config.php`, `docker-compose.yml`, `.htaccess`, `web.config`, `crossdomain.xml`, ...) via HEAD requests with 50 ms spacing |
| `forms` | standard, full | Password fields in GET forms, `autocomplete=on` on password forms, POST password forms without an apparent CSRF token |
| `links` | standard, full | HTTP links on HTTPS pages (mixed content), `mailto:` address exposure |
| `scripts` | standard, full | External scripts loaded over HTTP, inline script counts |
| `meta-tags` | standard, full | `<meta name="generator">` disclosure, meta-refresh redirects |
| `http-methods` | full | Enabled `TRACE`, `TRACK`, `PUT`, `DELETE`, `PATCH`, `OPTIONS` |
| `ssl-config` | full | Placeholder that flags HTTPS targets for dedicated tooling (testssl.sh, sslyze) |

Profile membership comes from `get_all_checks()`:

- **quick** — 6 checks: `http-headers`, `security-headers`, `cookie-security`, `tls-certificate`, `info-disclosure`, `tech-fingerprint`
- **standard** — 16 checks: quick + `csp`, `cors`, `robots-txt`, `sitemap`, `dir-listing`, `sensitive-files`, `forms`, `links`, `scripts`, `meta-tags`
- **full** — 18 checks: standard + `http-methods`, `ssl-config`

## Behavior notes

- Every check is independent: a check that errors is logged and the scan continues.
- Header-derived checks (`http-headers`, `security-headers`, `cookie-security`, `csp`, `cors`, `info-disclosure`) issue one GET per check; body checks (`tech-fingerprint`, `dir-listing`, `forms`, `links`, `scripts`, `meta-tags`) parse the HTML with `select`.
- `sensitive-files` is the only path-probing check; it HEAD-probes each path with a 50 ms delay between probes.
- The CLI scan command (`openre scan quick|standard|full`) filters out `sensitive-files` when the user passes neither `--checks` nor `--exclude`.
- `tls-certificate` reports plain-HTTP targets at High severity with remediation steps; successful HTTPS access is recorded as Info.

## Severity conventions

Findings carry `Severity` (Info/Low/Medium/High/Critical), `Confidence`, a `Category` (e.g. `SecurityMisconfiguration`, `InformationDisclosure`, `Configuration`), evidence with the observed header/body data, and — for the misconfiguration checks — structured `RemediationGuidance` (summary, steps, effort, priority). Typical severities: missing HSTS/CSP = High, wildcard CORS with credentials = High, password field in a GET form = High, missing `X-Frame-Options` = Medium, cookie without `Secure` = Medium, `TRACE`/`TRACK` enabled = Medium, `PUT`/`DELETE` enabled = High, generator/version disclosure = Low.

## Using check names

```bash
# Only the header-focused checks
openre scan standard https://example.org --checks http-headers,security-headers,csp,cors

# Full profile minus the noisy ones
openre scan full https://example.org --exclude robots-txt,sitemap,meta-tags
```

Check names are also the `ruleId` values in SARIF output (see [sarif.md](sarif.md)) and the `plugin_source` field on every finding.

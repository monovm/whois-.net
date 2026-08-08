# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — unreleased

First release. A ground-up .NET rewrite of [`monovm/whois-php`](https://github.com/monovm/whois-php),
sharing its server table and its detection knowledge but not its structure.

### Added

- `IWhoisClient` — async lookups and availability checks, with `CancellationToken` throughout.
- `WhoisRecord` — strongly typed registration data: registrar, dates, name servers, EPP statuses,
  DNSSEC, and the four contact roles, plus every raw key/value the reply carried.
- RDAP support alongside WHOIS port 43, chosen per suffix, behind one API.
- Referral following: a thin registry reply is followed to the registrar's own server for the full
  record, while the registry's reply stays authoritative for the verdict.
- An extensible detection chain: `IAvailabilityRule` ordered by priority, each verdict carrying the
  rule that decided it and the text that triggered it.
- Transport decorators for caching, retry with back-off, per-host rate limiting and logging.
- `WhoisClientBuilder` and `services.AddWhois(…)` for configuration and dependency injection.
- Server definitions from the bundled table, a JSON file, the `MONOVM_WHOIS_DEFINITIONS`
  environment variable, or code — layered, and overriding suffix by suffix.
- Longest-suffix matching, so `www.example.co.uk` resolves to `example.co.uk`.
- IDN handling: punycode on the wire by default, Unicode for the registries that want it, results
  returned in whichever form the caller used.
- `MonoVM.Whois.Cli`, a `dotnet tool` for lookups from the shell.
- `MonoVM.Whois.Compatibility` — `Checker` and `WhoisHandler` in the shape the PHP package exposes
  them, for code being ported.
- Targets `net9.0`, `net8.0` and `netstandard2.0`.

### Changed from the PHP package

Every difference below is in the same direction: never report a registered domain as free.

- A server that refuses to answer — rate limiting, a blocked client, a retired port 43, an RDAP
  403 or 5xx, an empty reply, an IP-registry banner on a mismatched suffix — reports `error`
  rather than `available`.
- An empty `available` marker in the server table no longer matches every reply. PHP's `strpos()`
  returns `0` for an empty needle, which is not `false`.
- A bare `404` anywhere in a reply is no longer read as availability; only a genuine RDAP 404 is.
- Keys padded with dots (`status.............: Registered`) are recognised.
- DENIC's `Status: invalid` is no longer read as availability.
- A premium or reserved name reports `IsPremium()`, and `IsAvailable()` is false.
- Junk input reports `invalid` rather than `available`.
- Suffixes are matched longest-first and subdomains are stripped, rather than splitting at the
  first dot.
- TLS certificates are validated by default.
- Detection patterns are compiled once per process rather than rebuilt per call, and the server
  table is parsed once per process rather than per lookup.

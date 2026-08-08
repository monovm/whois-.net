# MonoVM.Whois

**Domain WHOIS and RDAP lookups for .NET — with availability detection you can actually trust.**

[![NuGet](https://img.shields.io/nuget/v/MonoVM.Whois.svg)](https://www.nuget.org/packages/MonoVM.Whois/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A .NET library for retrieving domain registration data and checking whether a name can be
registered, over WHOIS (port 43) and RDAP. Built around interfaces, async, a curated server table
for 870+ suffixes, and a detection rule chain you can extend.

```csharp
using MonoVM.Whois;

using var client = new WhoisClient();

var result = await client.LookupAsync("monovm.com");

Console.WriteLine(result.Status);                 // Registered
Console.WriteLine(result.Record?.Registrar);      // the sponsoring registrar
Console.WriteLine(result.Record?.ExpiresOn);      // 2027-05-14T00:00:00+00:00
Console.WriteLine(result.Verdict?.Reason);        // why it decided that
```

---

## Contents

- [Install](#install)
- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [The one rule: never report a registered domain as free](#the-one-rule-never-report-a-registered-domain-as-free)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Extending it](#extending-it)
- [Dependency injection](#dependency-injection)
- [Command line tool](#command-line-tool)
- [Internationalised domains](#internationalised-domains)
- [Server table](#server-table)
- [Static convenience API](#static-convenience-api)
- [Testing](#testing)
- [License](#license)

---

## Install

```bash
dotnet add package MonoVM.Whois
```

Targets `net9.0`, `net8.0` and `netstandard2.0`, so it runs on .NET 8+, .NET Framework 4.6.2+,
Mono, Unity and Xamarin. The only dependencies are the `Microsoft.Extensions.*` abstractions.

The command line tool is a separate package:

```bash
dotnet tool install --global MonoVM.Whois.Cli
```

---

## What it does

| | |
|---|---|
| **Availability** | Is this name free to register? Answered from positive evidence only. |
| **Registration records** | Registrar, dates, name servers, EPP statuses, DNSSEC, contacts — strongly typed. |
| **Two protocols** | WHOIS port 43 and RDAP, chosen per suffix, behind one API. |
| **870+ suffixes** | Bundled, overridable per suffix, extensible from file or code. |
| **Referral following** | Thin registry replies are followed to the registrar for the full record. |
| **Async throughout** | `CancellationToken` everywhere, bulk checks with bounded parallelism. |
| **Caching and pacing** | An in-memory response cache and per-host rate limiting, both configurable. |
| **Explainable** | Every verdict carries the rule that decided it and the text that triggered it. |

---

## Quick start

### One domain

```csharp
using var client = new WhoisClient();

var result = await client.LookupAsync("example.co.uk");

result.Status;        // Available | Registered | Premium | Invalid | Error | Unknown
result.IsAvailable;   // bool
result.Domain;        // example (Sld) + .co.uk (Tld), punycode and unicode forms
result.Record;        // parsed registration record, or null
result.RawText;       // the registry's reply, verbatim
result.Verdict;       // status, reason, deciding rule, matched evidence
result.Duration;      // how long it took
```

Input is normalised, so all of these reach the same lookup:

```csharp
await client.LookupAsync("example.co.uk");
await client.LookupAsync("WWW.Example.CO.UK.");
await client.LookupAsync("https://shop.example.co.uk/cart?id=1");
```

### Just the answer

```csharp
if (await client.IsAvailableAsync("some-new-idea.com"))
{
    // free to register
}
```

### Many domains

```csharp
var statuses = await client.CheckAsync(new[] { "monovm", "google.com", "bing.net" });

// monovm.com   -> Registered
// monovm.net   -> Registered
// monovm.org   -> Registered
// monovm.info  -> Registered
// google.com   -> Registered
// bing.net     -> Registered
```

A name given without a suffix is expanded across `PopularTlds`. Duplicates are looked up once, and
the lookups run concurrently up to `MaxDegreeOfParallelism`.

To stream results as they arrive, in the order asked for:

```csharp
await foreach (var result in client.LookupManyAsync(candidates, cancellationToken))
{
    Console.WriteLine($"{result.Name,-24} {result.Status}");
}
```

### The record

```csharp
var record = (await client.LookupAsync("example.com")).Record;

record.Registrar;              // "Example Registrar, LLC"
record.CreatedOn;              // DateTimeOffset?
record.ExpiresOn;
record.TimeUntilExpiry();      // TimeSpan?
record.NameServers;            // ["a.iana-servers.net", "b.iana-servers.net"]
record.Statuses;               // ["clientDeleteProhibited", "clientTransferProhibited"]
record.HasStatus("transferProhibited");
record.DnsSecEnabled;          // bool?
record.Registrant?.Organization;
record.Registrant?.Country;
record.Field("Registry Domain ID");   // any key the reply carried, recognised or not
```

Every key/value pair the reply contained is in `record.Fields`, so nothing is lost to the parser's
opinion of what matters. Redaction placeholders ("REDACTED FOR PRIVACY" and its cousins) are kept
there but are not promoted to typed properties — `Registrant.Email` is `null` rather than the word
"REDACTED".

### Why it decided that

```csharp
var verdict = (await client.LookupAsync("example.com")).Verdict!;

verdict.Status;      // Registered
verdict.DecidedBy;   // "general-unavailability"
verdict.Reason;      // "the reply states the name is registered"
verdict.Evidence;    // the pattern that matched
```

Turn on `CollectFullTrace` and `verdict.Trace` lists every rule that was consulted, in order.

---

## The one rule: never report a registered domain as free

Selling someone a domain that is already taken is the failure that matters, and it is easy to build
a WHOIS client that does it. The trap is reasoning from absence: "this reply has no registration
fields, so the name must be unregistered."

Every one of these has no registration fields either:

- a rate-limit notice (`request limit exceeded`, `Maximum query rate reached`);
- a blocked client (`Requests of this client are not permitted`);
- a registry that retired port 43 in favour of RDAP;
- an HTTP 403 or 500 from an RDAP endpoint;
- a legal preamble with the record missing;
- a suffix mapped to the wrong server — the IP registries answer `%ERROR:101: no entries found` to
  every domain query;
- a truncated read, or an empty one.

**Availability is only ever concluded from positive evidence.** Anything else is an `Error`, which
means "ask again", not "it's free". `Error` is deliberately not folded into `Available`.

The one exception is opt-in per suffix: a handful of registries genuinely answer an unregistered
name with nothing but their banner, and those carry `available_when_empty` in the server table.
Even then the rule fires last, after every refusal and every registration signal has been ruled
out.

---

## Architecture

A lookup is five steps, each behind its own interface:

```
"HTTPS://WWW.Example.CO.UK/x"
        │
        ▼
  IDomainNameParser ──── normalise, split at the longest known suffix
        │                            │
        │                            └── IWhoisServerRegistry ◄── IWhoisServerDefinitionSource
        ▼                                                            (bundled │ file │ code)
  IWhoisTransportFactory
        │
        ▼
  ┌──────────────────────────────────────────────┐
  │ logging → caching → referrals → rate limit → │   decorators, each optional
  │ retry → Whois43Transport | RdapHttpTransport │
  └──────────────────────────────────────────────┘
        │
        ▼
  IAvailabilityAnalyzer ── an ordered chain of IAvailabilityRule
        │
        ▼
  IWhoisRecordParser ───── RDAP (jCard/JSON) │ key-value text
        │
        ▼
  WhoisLookupResult
```

`WhoisClient` contains only the sequencing. The sequence rarely changes; the steps often do.

### Patterns, and what each one buys

| Pattern | Where | Why |
|---|---|---|
| **Facade** | `WhoisClient` | One call instead of five collaborators. |
| **Strategy** | `IWhoisTransport`, `IWhoisRecordParser` | Port 43 and RDAP are interchangeable; so are text and JSON records. |
| **Chain of responsibility** | `IAvailabilityRule` | The order of the rules *is* the priority: refusals before verdicts, "registered" before "free". |
| **Decorator** | caching, retry, rate limit, referral, logging | Cross-cutting behaviour that neither transport has to know about. |
| **Factory** | `IWhoisTransportFactory` | Picks the protocol and assembles the decorator stack. |
| **Repository** | `IWhoisServerRegistry` | One place that answers "who serves this suffix?". |
| **Composite** | definition sources, record parsers | Layer overrides suffix by suffix; try parsers until one fits. |
| **Builder** | `WhoisClientBuilder`, `WhoisRecordBuilder` | Six optional collaborators, and a record assembled field by field from an unpredictable document. |
| **Value object** | `DomainName` | Immutable, equal by value, holds both the punycode and Unicode forms. |
| **Options** | `WhoisOptions` | Binds to `IConfiguration`; validated once at construction. |
| **Null object** | `NullWhoisResponseCache` | Caching off is a cache, not a branch in every call site. |

### SOLID, concretely

- **Single responsibility** — the transport does not interpret replies, and the analyzer does not
  touch the network. That split is what lets every behavioural test in this repository run offline.
- **Open/closed** — a registry with unusual wording is a new `IAvailabilityRule`; a new suffix is a
  JSON line or one `AddServer` call. Neither requires touching this library.
- **Liskov** — every transport honours the same contract: return the reply, throw a
  `WhoisException` subclass, never interpret.
- **Interface segregation** — `IDomainAvailabilityChecker` is two methods, so callers who only want
  a yes or no do not depend on the record model.
- **Dependency inversion** — `WhoisClient` depends on six interfaces and constructs none of them
  unless you leave it to.

---

## Configuration

```csharp
using var client = WhoisClient.CreateBuilder()
    .WithWhois43Timeout(TimeSpan.FromSeconds(5))
    .WithRdapTimeout(TimeSpan.FromSeconds(20))
    .WithPopularTlds(".com", ".dev", ".io")
    .WithCache(TimeSpan.FromMinutes(15))
    .WithRetry(maxAttempts: 3, delay: TimeSpan.FromMilliseconds(400))
    .WithRateLimit(TimeSpan.FromMilliseconds(500))
    .WithMaxParallelism(4)
    .WithReferralFollowing(enabled: true, maxDepth: 2)
    .WithFullTrace()
    .Build();
```

| Option | Default | What it does |
|---|---|---|
| `Whois43Timeout` | 10 s | Connect and read timeout for port 43. |
| `RdapTimeout` | 30 s | Total timeout for an RDAP request. |
| `ValidateTlsCertificates` | `true` | TLS verification for RDAP. See the note below. |
| `PopularTlds` | `.com .net .org .info` | Tried when the caller gives a bare label. |
| `UnicodeQueryTlds` | `.de` | Registries queried in Unicode rather than punycode. |
| `FollowRegistrarReferrals` | `true` | Follow a thin reply to the registrar's server. |
| `MaxReferralDepth` | 2 | How far to follow. |
| `MaxRetryAttempts` | 2 | Retries for a transient failure. |
| `RetryDelay` | 500 ms | Base back-off, doubled each attempt. |
| `EnableCache` / `CacheLifetime` | on / 5 min | In-memory response cache. |
| `MaxDegreeOfParallelism` | 8 | Concurrent lookups in a bulk check. |
| `MinDelayBetweenQueriesPerHost` | 250 ms | Pacing, per host. |
| `ParseRecords` | `true` | Parse replies into `WhoisRecord`. |
| `CollectFullTrace` | `false` | Keep every rule consulted, not just the deciding one. |
| `ThrowOnLookupFailure` | `false` | Throw instead of returning an `Error` result. |
| `DefinitionsFilePath` | – | JSON merged over the bundled table. |
| `UseBundledDefinitions` | `true` | Whether to load the bundled table at all. |

> **On TLS.** A few registry RDAP endpoints still serve incomplete certificate chains, which
> tempts a client into skipping verification altogether. Silently accepting any certificate is not
> a default this library will ship. If you need it for a specific registry, turn it off
> deliberately with `WithTlsValidation(false)` — and turn it back on when they fix their chain.

---

## Extending it

### Add or repoint a suffix

From code:

```csharp
var client = WhoisClient.CreateBuilder()
    .AddServer(".example", "socket://whois.example.test", available: "No match for")
    .AddServer(".shop", "https://rdap.gmoregistry.net/rdap/domain/")
    .Build();
```

From a file, merged over the bundled table suffix by suffix:

```json
[
  {
    "extensions": ".example,.test",
    "uri": "socket://whois.example.test",
    "available": "No match for",
    "premium": "Reserved by the registry",
    "available_when_empty": "false",
    "comment": "why this entry looks the way it does"
  }
]
```

```csharp
.WithDefinitionsFile("/etc/whois/overrides.json")
```

…or point the `MONOVM_WHOIS_DEFINITIONS` environment variable at it, which needs no code change at
all.

### Teach it a registry's dialect

```csharp
public sealed class ExampleRegistryRule : AvailabilityRule
{
    public override string Name => "example-registry";

    // Before the general patterns, after the refusal checks.
    public override int Order => AvailabilityRuleOrder.TldUnavailability - 1;

    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
        => context.Tld == ".example" && context.Contains("Objekt nicht gefunden")
            ? AvailabilityRuleResult.Available("the .example registry says the name is free")
            : AvailabilityRuleResult.Continue;
}

var client = WhoisClient.CreateBuilder().AddRule(new ExampleRegistryRule()).Build();
```

`AvailabilityContext` hands every rule the same pre-computed views of the reply — lower-cased,
banner-stripped, split into lines — so a chain of a dozen rules still makes one pass over the text.

### Replace a whole step

Every collaborator can be supplied directly: `WithRegistry`, `WithTransportFactory`, `WithAnalyzer`,
`AddRecordParser`, `WithHttpClient`, `WithLogging`. Substituting `IWhoisTransportFactory` is how the
test suite runs entirely offline.

---

## Dependency injection

```csharp
services.AddWhois(options =>
{
    options.Whois43Timeout = TimeSpan.FromSeconds(5);
    options.MaxDegreeOfParallelism = 16;
});
```

or bound from configuration:

```csharp
services.Configure<WhoisOptions>(configuration.GetSection(WhoisOptions.SectionName));
services.AddWhois();
```

with an `HttpClient` from `IHttpClientFactory`:

```csharp
services.AddHttpClient("rdap").AddPolicyHandler(retryPolicy);
services.AddWhois(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("rdap"));
```

Everything registers as a singleton, and everything uses `TryAdd`, so registering your own
implementation first replaces it:

```csharp
services.AddSingleton<IAvailabilityAnalyzer, MyAnalyzer>();
services.AddWhois();
```

`IWhoisClient`, `IWhoisLookup` and `IDomainAvailabilityChecker` all resolve to the same instance —
inject the narrowest one your class actually needs.

---

## Command line tool

```bash
dotnet tool install --global MonoVM.Whois.Cli
```

```console
$ monovm-whois monovm.com bing
monovm.com  unavailable  expires 2027-05-14
bing.com    unavailable  expires 2026-03-29
bing.net    unavailable  expires 2026-04-01
bing.org    available
bing.info   unavailable  expires 2026-08-01

$ monovm-whois example.co.uk --record
example.co.uk  unavailable  expires 2026-12-10
    registrar     Example Registrar Ltd
    created       1996-08-01
    expires       2026-12-10
    nameservers   ns1.example.co.uk, ns2.example.co.uk

$ monovm-whois monovm --tlds .com,.dev,.io --json
$ monovm-whois example.com --trace
$ monovm-whois --servers | wc -l
```

Exit codes: `0` every name got a verdict, `1` at least one lookup failed, `2` bad arguments.

---

## Internationalised domains

Both forms work, and each registry is queried the way it expects:

```csharp
await client.LookupAsync("bücher.com");           // queried as xn--bcher-kva.com
await client.LookupAsync("xn--bcher-kva.com");    // the same lookup
await client.LookupAsync("münchen.de");           // queried as münchen.de
```

Punycode goes on the wire by default, because Verisign and most registries answer "No match" to a
Unicode query — which would read as availability. DENIC is the exception and gets the Unicode form;
add others with `UnicodeQueryTlds`. Results come back in whichever form you asked with.

---

## Server table

870+ extensions ship with the package, over WHOIS port 43 and RDAP. Inspect them at runtime:

```csharp
client.Servers.SupportedTlds;             // [".abogado", ".ac", ".academy", …]
client.Servers.Supports(".dev");          // true
client.Servers.FindLongestSuffix("a.b.example.co.uk");   // ".co.uk"
client.Servers.TryGet(".com", out var server);
server.Uri;                               // "socket://whois.verisign-grs.com"
server.AvailableMatch;                    // "No match for"
```

A dozen entries in the table were corrected against the live registries, each because the original
made every domain under it look available. Those entries carry a `comment` explaining what was
wrong. Where IANA publishes no WHOIS server at all, the suffix is absent and reports `Invalid` —
which is the truth, and better than an answer that is confidently wrong.

---

## Static convenience API

`MonoVM.Whois.Compatibility` offers a minimal static surface for scripts and quick checks — one
call, no client to construct, lower-case status strings:

```csharp
using MonoVM.Whois.Compatibility;

var results = Checker.Whois(new[] { "monovm", "google.com" });
// { "monovm.com": "unavailable", …, "google.com": "unavailable" }

var handler = WhoisHandler.Whois("monovm.com");
handler.IsAvailable();
handler.IsPremium();
handler.GetTld();          // ".com"
handler.GetSld();          // "monovm"
handler.GetWhoisMessage();
```

New code should use `IWhoisClient` — async, cancellable, and it tells you what went wrong.

### Design decisions worth knowing

Every one of these is in the same direction: this library would rather say "I could not tell" than
"it's free".

| Situation | Verdict here |
|---|---|
| Rate-limited, blocked, or retired endpoint | `error`, never `available` |
| RDAP 403 / 5xx | `error`; only a genuine 404 is a verdict |
| Empty reply | `error`, unless the suffix opted in via `available_when_empty` |
| IP-registry banner on a mismatched suffix | `error` |
| Premium / reserved name | `IsPremium()`, and `IsAvailable()` is false |
| Junk input | `invalid` |
| Empty `available` marker in the table | ignored, matches nothing |
| `status.....: Registered` (padded keys) | recognised |
| DENIC `Status: invalid` | registered |
| Suffix matching | longest known suffix wins, subdomains stripped |
| IDNs | punycode on the wire, per-registry exceptions |
| Bare `404` in the middle of a reply | not a verdict; only a real RDAP 404 counts |
| Detection patterns | compiled once per process |

---

## Testing

```bash
git clone https://github.com/monovm/whois-dotnet
cd whois-dotnet
dotnet test
```

The whole suite runs offline. The wire lives behind `IWhoisTransport`, so detection, parsing,
caching, retry, referral following and the client's own sequencing are all tested against captured
replies — including the awkward ones: dotted keys, rate-limit notices, IP-registry banners, RDAP
error documents, and legal boilerplate that contains the word "available".

---

## License

[MIT](LICENSE) · [MonoVM.com](https://monovm.com) · dev@monovm.com

using System.Text.RegularExpressions;

namespace MonoVM.Whois.Detection.Patterns;

/// <summary>
/// Replies in which the server did not answer the question: it does not serve the suffix, it is
/// busy, it is rate-limiting the client, or it has retired the endpoint.
/// </summary>
/// <remarks>
/// <para>
/// These are the patterns that keep the library honest. Every reply of this shape contains no
/// registration fields and no "not found" wording, which is exactly the shape of an available
/// domain — so an implementation that only looks for records will report every domain behind a
/// rate limiter as free to register. That is the failure mode this table exists to prevent.
/// </para>
/// </remarks>
internal static class RefusalSignals
{
    /// <summary>Wording that means "this server does not serve that suffix".</summary>
    public static readonly string[] UnsupportedFragments =
    {
        "tld is not supported",
        "tld not supported",
        "extension not supported",
        "domain extension not supported",
        "unsupported tld",
        "unsupported domain extension",
        "this tld is not supported",
        "the tld is not supported",
        "whois server not known",
        "no whois server",
        "whois service not available",
        "not supported by this whois server",
        "extension is not supported",
        "domain type not supported",
        "tld not available",
        "extension not available",
        "no server found for",
        "server not found for",
        "whois not available for",
        "no whois available for",

        // Banners of the regional IP-number registries. Reaching one of these means the suffix is
        // mapped to the wrong server — and they answer "%ERROR:101: no entries found" to every
        // domain query, which reads as availability for every domain under that suffix.
        "this is the ripe database query service",
        "the objects are in rpsl format",
        "[whois.apnic.net]",
        "apnic whois service",
        "american registry for internet numbers",
        "whois.arin.net",
        "lacnic whois server",
        "afrinic whois server",
    };

    /// <summary>The same idea, where the wording varies too much for a fixed string.</summary>
    public static readonly Regex[] UnsupportedPatterns = PatternCatalog.CompileAll(
        @"tld\s+(?:is\s+)?not\s+supported",
        @"extension\s+(?:is\s+)?not\s+supported",
        @"unsupported\s+(?:tld|extension|domain)",
        @"no\s+whois\s+(?:server|service)\s+(?:available|found)",
        @"whois\s+(?:server\s+)?not\s+(?:known|available|found)",
        @"(?:server|service)\s+not\s+(?:available|found)\s+for");

    /// <summary>
    /// Conditions that are the server's problem and will probably clear on their own.
    /// </summary>
    /// <remarks>
    /// The bare word "timeout" is deliberately absent: it appears in perfectly good records, and
    /// this table is consulted before the record checks.
    /// </remarks>
    public static readonly string[] TransientFragments =
    {
        "server is busy",
        "server busy",
        "please try again later",
        "try again later",
        "service temporarily unavailable",
        "temporarily unavailable",
        "rate limit exceeded",
        "too many requests",
        "quota exceeded",
        "connection timed out",
        "connection timeout",
        "request timeout",
        "query timeout",
        "read timeout",
    };

    /// <summary>
    /// The server answered, but with a refusal rather than a verdict: rate limiting, a blocked
    /// client, or a port-43 endpoint that now only serves RDAP.
    /// </summary>
    public static readonly Regex[] NoVerdictPatterns = PatternCatalog.CompileAll(
        // Rate limiting, in the wording used by .pl, .lu, .cz, .ru and others.
        @"request(?:s)?\s+limit\s+exceeded",
        @"quer(?:y|ies)\s+limit\s+exceeded",
        @"limit\s+exceeded",
        @"maximum\s+quer(?:y|ies)\s+rate",
        @"quer(?:y|ies)\s+rate\s+exceeded",
        @"excessive\s+querying",
        @"too\s+many\s+quer(?:y|ies)",
        @"lookup\s+quota",

        // The client is blocked, or must use a web form (.li, .ch).
        @"requests?\s+of\s+this\s+client\s+(?:are|is)\s+not\s+permitted",
        @"access\s+to\s+this\s+whois\s+server\s+is\s+(?:denied|blocked)",

        // Port 43 retired in favour of RDAP (.shop and other GMO/Identity registries).
        @"whois\s+service\s+has\s+been\s+retired",
        @"(?:queries|service)\s+are\s+now\s+served\s+via\s+rdap",
        @"rdap\s+base\s+url");
}

using System;
using System.Collections.Generic;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Configuration;

/// <summary>
/// Everything about a lookup that a caller might reasonably want to change.
/// </summary>
/// <remarks>
/// Bound through <c>Microsoft.Extensions.Options</c> when the library is used from a host, or set
/// directly through <see cref="WhoisClientBuilder"/> when it is not. Defaults are chosen for a
/// well-behaved client: modest timeouts, retries on transient failures, a short response cache, and
/// no more than a handful of registries queried at once.
/// </remarks>
public sealed class WhoisOptions
{
    /// <summary>The configuration section this type binds to by convention.</summary>
    public const string SectionName = "Whois";

    /// <summary>Environment variable naming a JSON file of extra or replacement server definitions.</summary>
    public const string DefinitionsEnvironmentVariable = "MONOVM_WHOIS_DEFINITIONS";

    /// <summary>Connect and read timeout for port-43 lookups. Default: 10 seconds.</summary>
    public TimeSpan Whois43Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Total timeout for an RDAP request. Default: 30 seconds.</summary>
    public TimeSpan RdapTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Whether to verify TLS certificates on RDAP requests. Default: <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// A handful of registry endpoints still serve incomplete certificate chains, which tempts a
    /// client into skipping verification. Silently accepting any certificate is not a default this
    /// library is willing to ship; turn it off deliberately, for the registries that need it, if
    /// you must.
    /// </remarks>
    public bool ValidateTlsCertificates { get; set; } = true;

    /// <summary>
    /// Suffixes tried when the caller supplies a bare label such as <c>"monovm"</c>.
    /// </summary>
    public IList<string> PopularTlds { get; set; } = new List<string> { ".com", ".net", ".org", ".info" };

    /// <summary>
    /// Registries that want internationalised names in Unicode rather than punycode.
    /// </summary>
    /// <remarks>
    /// DENIC answers <c>Status: invalid</c> for <c>xn--mnchen-3ya.de</c> but resolves
    /// <c>münchen.de</c> correctly. Almost every other registry is the other way round — Verisign
    /// answers "No match" to a Unicode query, which would read as availability — so punycode is the
    /// default and this set is the exception list.
    /// </remarks>
    public ISet<string> UnicodeQueryTlds { get; set; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".de" };

    /// <summary>
    /// Whether a thin registry reply naming the registrar's own WHOIS server should be followed to
    /// fetch the full record. Default: <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Verisign and other thin registries return only the registrar, the status codes and the
    /// dates. The contact details, if they survive redaction at all, live on the registrar's server.
    /// Following the referral costs a second round trip and never changes the availability verdict.
    /// </remarks>
    public bool FollowRegistrarReferrals { get; set; } = true;

    /// <summary>How many referrals deep to follow before giving up. Default: 2.</summary>
    public int MaxReferralDepth { get; set; } = 2;

    /// <summary>How many times to retry a transient failure. Default: 2.</summary>
    public int MaxRetryAttempts { get; set; } = 2;

    /// <summary>Base delay before the first retry; doubled on each further attempt. Default: 500 ms.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Whether replies are cached in memory. Default: <see langword="true"/>.</summary>
    public bool EnableCache { get; set; } = true;

    /// <summary>How long a cached reply stays fresh. Default: 5 minutes.</summary>
    public TimeSpan CacheLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How many lookups a bulk check runs at once. Default: 8.</summary>
    public int MaxDegreeOfParallelism { get; set; } = 8;

    /// <summary>
    /// Minimum spacing between two queries to the same host. Default: 250 ms.
    /// </summary>
    /// <remarks>
    /// Registries rate-limit per client address, and a rate-limited reply is worse than a slow one:
    /// it carries no verdict at all. Pacing is cheaper than retrying.
    /// </remarks>
    public TimeSpan MinDelayBetweenQueriesPerHost { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>Whether to parse replies into <see cref="WhoisRecord"/>. Default: <see langword="true"/>.</summary>
    public bool ParseRecords { get; set; } = true;

    /// <summary>
    /// Whether the verdict keeps every rule it consulted, not just the one that decided.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool CollectFullTrace { get; set; }

    /// <summary>
    /// Whether a failed lookup throws instead of returning a result with
    /// <see cref="DomainAvailabilityStatus.Error"/>. Default: <see langword="false"/>.
    /// </summary>
    public bool ThrowOnLookupFailure { get; set; }

    /// <summary>
    /// A JSON file whose definitions are merged over the bundled table.
    /// </summary>
    /// <remarks>
    /// Falls back to the <see cref="DefinitionsEnvironmentVariable"/> environment variable when
    /// unset. Entries replace bundled ones suffix by suffix, so a file naming only <c>.com</c>
    /// leaves the other 800-odd alone.
    /// </remarks>
    public string? DefinitionsFilePath { get; set; }

    /// <summary>Whether the table bundled with the package is loaded at all. Default: <see langword="true"/>.</summary>
    public bool UseBundledDefinitions { get; set; } = true;

    /// <summary>Extra definition sources, applied in order after the bundled table.</summary>
    public IList<IWhoisServerDefinitionSource> AdditionalSources { get; }
        = new List<IWhoisServerDefinitionSource>();

    /// <summary>Individual server definitions to add or override, applied last.</summary>
    public IList<WhoisServerDefinition> AdditionalServers { get; } = new List<WhoisServerDefinition>();

    /// <summary>User agent sent on RDAP requests.</summary>
    public string UserAgent { get; set; } = "MonoVM.Whois (+https://github.com/monovm/whois-dotnet)";

    /// <summary>Throws when the options contradict themselves.</summary>
    /// <exception cref="WhoisDefinitionException">A value is out of range or the set is unusable.</exception>
    public void Validate()
    {
        if (Whois43Timeout <= TimeSpan.Zero)
        {
            throw new WhoisDefinitionException($"{nameof(Whois43Timeout)} must be greater than zero.");
        }

        if (RdapTimeout <= TimeSpan.Zero)
        {
            throw new WhoisDefinitionException($"{nameof(RdapTimeout)} must be greater than zero.");
        }

        if (MaxRetryAttempts < 0)
        {
            throw new WhoisDefinitionException($"{nameof(MaxRetryAttempts)} must not be negative.");
        }

        if (RetryDelay < TimeSpan.Zero)
        {
            throw new WhoisDefinitionException($"{nameof(RetryDelay)} must not be negative.");
        }

        if (MaxReferralDepth < 0)
        {
            throw new WhoisDefinitionException($"{nameof(MaxReferralDepth)} must not be negative.");
        }

        if (MaxDegreeOfParallelism < 1)
        {
            throw new WhoisDefinitionException($"{nameof(MaxDegreeOfParallelism)} must be at least 1.");
        }

        if (CacheLifetime <= TimeSpan.Zero && EnableCache)
        {
            throw new WhoisDefinitionException($"{nameof(CacheLifetime)} must be greater than zero when the cache is enabled.");
        }

        if (PopularTlds is null || PopularTlds.Count == 0)
        {
            throw new WhoisDefinitionException($"{nameof(PopularTlds)} must name at least one suffix.");
        }

        if (!UseBundledDefinitions && AdditionalSources.Count == 0 && AdditionalServers.Count == 0 &&
            string.IsNullOrWhiteSpace(DefinitionsFilePath) &&
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(DefinitionsEnvironmentVariable)))
        {
            throw new WhoisDefinitionException(
                "The bundled definitions are disabled and no replacement source was configured, so no suffix could be served.");
        }
    }

    /// <summary>Returns the popular suffixes normalised to lower case with a leading dot.</summary>
    internal IReadOnlyList<string> NormalizedPopularTlds()
    {
        var result = new List<string>(PopularTlds.Count);
        foreach (var tld in PopularTlds)
        {
            var normalized = DomainName.NormalizeSuffix(tld);
            if (normalized.Length > 0 && !result.Contains(normalized))
            {
                result.Add(normalized);
            }
        }

        if (result.Count == 0)
        {
            throw new WhoisDefinitionException($"{nameof(PopularTlds)} must name at least one usable suffix.");
        }

        return result;
    }

    /// <summary>True when <paramref name="tld"/> should be queried in its Unicode form.</summary>
    internal bool PrefersUnicodeQuery(string tld)
        => UnicodeQueryTlds is not null && UnicodeQueryTlds.Contains(tld);
}

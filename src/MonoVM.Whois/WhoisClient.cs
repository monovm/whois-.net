using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Detection;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;
using MonoVM.Whois.Parsing;
using MonoVM.Whois.Registry;
using MonoVM.Whois.Transport;

namespace MonoVM.Whois;

/// <summary>
/// The façade over the whole pipeline: parse the input, find the registry, ask it, decide what the
/// answer means, and parse the record.
/// </summary>
/// <remarks>
/// <para>
/// Each of those five steps is a separate collaborator behind its own interface, and the client
/// itself contains only the sequencing. That is deliberate: the sequence almost never changes, and
/// the steps almost always do.
/// </para>
/// <para>
/// Thread-safe, and cheap to keep around. Building one parses the bundled table of 870-odd
/// suffixes, so register it as a singleton rather than constructing one per lookup.
/// </para>
/// </remarks>
public sealed class WhoisClient : IWhoisClient, IDisposable
{
    private readonly WhoisOptions _options;
    private readonly IWhoisServerRegistry _registry;
    private readonly IDomainNameParser _domainParser;
    private readonly IWhoisTransportFactory _transportFactory;
    private readonly IAvailabilityAnalyzer _analyzer;
    private readonly IWhoisRecordParser _recordParser;
    private readonly bool _ownsTransportFactory;

    /// <summary>Creates a client with the bundled table and default behaviour.</summary>
    public WhoisClient()
        : this(new WhoisOptions())
    {
    }

    /// <summary>Creates a client configured by <paramref name="options"/>.</summary>
    public WhoisClient(WhoisOptions options)
        : this(options, registry: null, transportFactory: null)
    {
    }

    /// <summary>Creates a client from options supplied by the host's configuration system.</summary>
    public WhoisClient(IOptions<WhoisOptions> options)
        : this((options ?? throw new ArgumentNullException(nameof(options))).Value)
    {
    }

    /// <summary>
    /// Creates a client from the parts, for hosts that resolve them from a container and for tests
    /// that substitute one of them.
    /// </summary>
    /// <param name="options">Configuration. Validated here, once.</param>
    /// <param name="registry">The suffix table. Built from <paramref name="options"/> when omitted.</param>
    /// <param name="transportFactory">The transport stack. Built from <paramref name="options"/> when omitted.</param>
    /// <param name="analyzer">The rule chain. Defaults to the built-in rules.</param>
    /// <param name="recordParser">The record parsers. Defaults to RDAP plus key/value.</param>
    /// <param name="domainParser">The input parser. Defaults to one over <paramref name="registry"/>.</param>
    public WhoisClient(
        WhoisOptions options,
        IWhoisServerRegistry? registry = null,
        IWhoisTransportFactory? transportFactory = null,
        IAvailabilityAnalyzer? analyzer = null,
        IWhoisRecordParser? recordParser = null,
        IDomainNameParser? domainParser = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();

        _registry = registry ?? WhoisServerRegistry.FromOptions(_options);
        _domainParser = domainParser ?? new DomainNameParser(_registry);
        _analyzer = analyzer ?? new AvailabilityAnalyzer(null, _options);
        _recordParser = recordParser ?? CompositeWhoisRecordParser.CreateDefault();

        if (transportFactory is null)
        {
            _transportFactory = new WhoisTransportFactory(_options);
            _ownsTransportFactory = true;
        }
        else
        {
            _transportFactory = transportFactory;
            _ownsTransportFactory = false;
        }
    }

    /// <summary>
    /// A process-wide client with default settings, for scripts and one-off calls.
    /// </summary>
    /// <remarks>
    /// Convenience, not a recommendation: in an application, register a <see cref="WhoisClient"/>
    /// as a singleton through <c>AddWhois</c> so it picks up your configuration, logging and
    /// <c>HttpClient</c>.
    /// </remarks>
    public static WhoisClient Shared => SharedInstance.Value;

    private static readonly Lazy<WhoisClient> SharedInstance =
        new Lazy<WhoisClient>(() => new WhoisClient(), isThreadSafe: true);

    /// <inheritdoc />
    public IWhoisServerRegistry Servers => _registry;

    /// <summary>The options this client is running with.</summary>
    public WhoisOptions Options => _options;

    /// <summary>Starts building a client with non-default behaviour.</summary>
    public static WhoisClientBuilder CreateBuilder() => new WhoisClientBuilder();

    /// <inheritdoc />
    public async Task<WhoisLookupResult> LookupAsync(string domain, CancellationToken cancellationToken = default)
    {
        if (domain is null)
        {
            throw new ArgumentNullException(nameof(domain));
        }

        if (!_domainParser.TryParse(domain, out var parsed, out var error))
        {
            return Invalid(domain, $"Unable to look up whois information for '{domain}': {error}.");
        }

        if (!parsed.HasTld)
        {
            return Invalid(
                domain,
                $"'{parsed.Sld}' carries no suffix. Give one, or use the bulk overload, which tries the popular suffixes.",
                parsed);
        }

        return await LookupCoreAsync(domain, parsed, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<WhoisLookupResult> LookupAsync(DomainName domain, CancellationToken cancellationToken = default)
    {
        if (domain is null)
        {
            throw new ArgumentNullException(nameof(domain));
        }

        return LookupCoreAsync(domain.Unicode, domain, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> IsAvailableAsync(string domain, CancellationToken cancellationToken = default)
    {
        var result = await LookupAsync(domain, cancellationToken).ConfigureAwait(false);
        return result.IsAvailable;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, DomainAvailabilityStatus>> CheckAsync(
        IEnumerable<string> domains,
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, DomainAvailabilityStatus>(StringComparer.OrdinalIgnoreCase);

        await foreach (var result in LookupManyAsync(domains, cancellationToken).ConfigureAwait(false))
        {
            results[result.Name] = result.Status;
        }

        return results;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<WhoisLookupResult> LookupManyAsync(
        IEnumerable<string> domains,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (domains is null)
        {
            throw new ArgumentNullException(nameof(domains));
        }

        var work = new List<Task<WhoisLookupResult>>();

        // Not disposed on purpose: a caller who abandons the enumeration part-way leaves lookups in
        // flight, and disposing the gate under them would turn an early break into an exception.
        var throttle = new SemaphoreSlim(_options.MaxDegreeOfParallelism, _options.MaxDegreeOfParallelism);

        foreach (var candidate in Expand(domains))
        {
            work.Add(RunThrottledAsync(candidate.Query, candidate.Domain, throttle, cancellationToken));
        }

        // Results are yielded in the order asked for, while the lookups themselves run concurrently
        // up to the configured degree of parallelism.
        foreach (var task in work)
        {
            yield return await task.ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsTransportFactory && _transportFactory is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    private async Task<WhoisLookupResult> RunThrottledAsync(
        string query,
        DomainName? domain,
        SemaphoreSlim throttle,
        CancellationToken cancellationToken)
    {
        await throttle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (domain is null)
            {
                return Invalid(query, $"Unable to look up whois information for '{query}'.");
            }

            return await LookupCoreAsync(query, domain, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            throttle.Release();
        }
    }

    private async Task<WhoisLookupResult> LookupCoreAsync(
        string query,
        DomainName domain,
        CancellationToken cancellationToken)
    {
        if (!domain.IsWellFormed)
        {
            return Invalid(query, $"'{domain.Ascii}' is not a well-formed domain name.", domain);
        }

        if (!_registry.TryGet(domain.AsciiTld, out var server))
        {
            return Invalid(
                query,
                $"No WHOIS or RDAP server is known for '{domain.Tld}'.",
                domain);
        }

        var whoisQuery = new WhoisQuery(domain, server, BuildQueryText(domain, server));
        var transport = _transportFactory.Create(server);
        var stopwatch = Stopwatch.StartNew();

        WhoisResponse response;
        try
        {
            response = await transport.QueryAsync(whoisQuery, cancellationToken).ConfigureAwait(false);
        }
        catch (WhoisException exception)
        {
            stopwatch.Stop();

            if (_options.ThrowOnLookupFailure)
            {
                throw;
            }

            return WhoisLookupResult.Failed(query, domain, exception, server, stopwatch.Elapsed);
        }

        stopwatch.Stop();

        var verdict = _analyzer.Analyze(new AvailabilityContext(response, server));

        WhoisRecord? record = null;
        if (_options.ParseRecords && verdict.Status is DomainAvailabilityStatus.Registered or DomainAvailabilityStatus.Premium)
        {
            record = _recordParser.Parse(response);
        }

        var result = WhoisLookupResult.FromResponse(query, response, verdict, server, record, stopwatch.Elapsed);

        if (_options.ThrowOnLookupFailure && result.Status == DomainAvailabilityStatus.Error)
        {
            throw new WhoisServerException(verdict.Reason, server.Host);
        }

        return result;
    }

    /// <summary>
    /// Chooses the form of the name to put on the wire.
    /// </summary>
    /// <remarks>
    /// Punycode by default: Verisign and most registries answer "No match" to a Unicode query,
    /// which would read as availability. DENIC and the others listed in
    /// <see cref="WhoisOptions.UnicodeQueryTlds"/> are the exception, and only over port 43 — a URL
    /// always carries the ASCII form.
    /// </remarks>
    private string BuildQueryText(DomainName domain, WhoisServerDefinition server)
        => server.Protocol == WhoisProtocol.Whois43 && _options.PrefersUnicodeQuery(server.Tld)
            ? domain.Unicode
            : domain.Ascii;

    private IEnumerable<Candidate> Expand(IEnumerable<string> domains)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var popular = _options.NormalizedPopularTlds();

        foreach (var input in domains)
        {
            if (input is null)
            {
                continue;
            }

            if (!_domainParser.TryParse(input, out var parsed, out _))
            {
                if (seen.Add(DomainNameNormalizer.Normalize(input)))
                {
                    yield return new Candidate(input, null);
                }

                continue;
            }

            if (parsed.HasTld)
            {
                if (seen.Add(parsed.Ascii))
                {
                    yield return new Candidate(input, parsed);
                }

                continue;
            }

            // A bare label: try it under each of the popular suffixes, which is what makes
            // "monovm" a useful thing to ask about.
            foreach (var tld in popular)
            {
                var expanded = parsed.WithTld(tld);
                if (seen.Add(expanded.Ascii))
                {
                    yield return new Candidate(expanded.Unicode, expanded);
                }
            }
        }
    }

    private static WhoisLookupResult Invalid(string query, string message, DomainName? domain = null)
        => WhoisLookupResult.Invalid(query, message, domain);

    private readonly struct Candidate
    {
        public Candidate(string query, DomainName? domain)
        {
            Query = query;
            Domain = domain;
        }

        public string Query { get; }

        public DomainName? Domain { get; }
    }
}

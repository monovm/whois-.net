using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Detection;
using MonoVM.Whois.Model;
using MonoVM.Whois.Parsing;
using MonoVM.Whois.Registry;
using MonoVM.Whois.Transport;

namespace MonoVM.Whois;

/// <summary>
/// Assembles a <see cref="WhoisClient"/> a step at a time.
/// </summary>
/// <remarks>
/// The client has six collaborators, all of them optional. A constructor taking six nullable
/// interfaces is a poor way to say that; a builder reads as what it is, and leaves room to add a
/// seventh without breaking anyone.
/// </remarks>
/// <example>
/// <code>
/// var client = WhoisClient.CreateBuilder()
///     .WithWhois43Timeout(TimeSpan.FromSeconds(5))
///     .WithPopularTlds(".com", ".dev", ".io")
///     .AddServer(".example", "socket://whois.example.test", available: "No match for")
///     .WithCache(TimeSpan.FromMinutes(15))
///     .Build();
/// </code>
/// </example>
public sealed class WhoisClientBuilder
{
    private readonly WhoisOptions _options = new WhoisOptions();
    private readonly List<IAvailabilityRule> _extraRules = new List<IAvailabilityRule>();
    private readonly List<IWhoisRecordParser> _parsers = new List<IWhoisRecordParser>();

    private IWhoisServerRegistry? _registry;
    private IWhoisTransportFactory? _transportFactory;
    private IAvailabilityAnalyzer? _analyzer;
    private IWhoisResponseCache? _cache;
    private ILoggerFactory? _loggerFactory;
    private HttpClient? _httpClient;

    /// <summary>Applies arbitrary changes to the options.</summary>
    public WhoisClientBuilder Configure(Action<WhoisOptions> configure)
    {
        if (configure is null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        configure(_options);
        return this;
    }

    /// <summary>Sets the connect and read timeout for port-43 lookups.</summary>
    public WhoisClientBuilder WithWhois43Timeout(TimeSpan timeout)
    {
        _options.Whois43Timeout = timeout;
        return this;
    }

    /// <summary>Sets the total timeout for RDAP requests.</summary>
    public WhoisClientBuilder WithRdapTimeout(TimeSpan timeout)
    {
        _options.RdapTimeout = timeout;
        return this;
    }

    /// <summary>Sets the suffixes tried when the caller supplies a bare label.</summary>
    public WhoisClientBuilder WithPopularTlds(params string[] tlds)
    {
        if (tlds is null || tlds.Length == 0)
        {
            throw new ArgumentException("At least one suffix is required.", nameof(tlds));
        }

        _options.PopularTlds = new List<string>(tlds);
        return this;
    }

    /// <summary>Turns the response cache on with the given lifetime.</summary>
    public WhoisClientBuilder WithCache(TimeSpan lifetime, IWhoisResponseCache? cache = null)
    {
        _options.EnableCache = true;
        _options.CacheLifetime = lifetime;
        _cache = cache;
        return this;
    }

    /// <summary>Turns the response cache off.</summary>
    public WhoisClientBuilder WithoutCache()
    {
        _options.EnableCache = false;
        _cache = NullWhoisResponseCache.Instance;
        return this;
    }

    /// <summary>Sets how many times a transient failure is retried, and the initial back-off.</summary>
    public WhoisClientBuilder WithRetry(int maxAttempts, TimeSpan? delay = null)
    {
        _options.MaxRetryAttempts = maxAttempts;
        if (delay.HasValue)
        {
            _options.RetryDelay = delay.Value;
        }

        return this;
    }

    /// <summary>Sets the minimum spacing between two queries to the same host.</summary>
    public WhoisClientBuilder WithRateLimit(TimeSpan minimumDelayPerHost)
    {
        _options.MinDelayBetweenQueriesPerHost = minimumDelayPerHost;
        return this;
    }

    /// <summary>Sets how many lookups a bulk check runs at once.</summary>
    public WhoisClientBuilder WithMaxParallelism(int degree)
    {
        _options.MaxDegreeOfParallelism = degree;
        return this;
    }

    /// <summary>Turns following of registrar referrals on or off.</summary>
    public WhoisClientBuilder WithReferralFollowing(bool enabled, int maxDepth = 2)
    {
        _options.FollowRegistrarReferrals = enabled;
        _options.MaxReferralDepth = maxDepth;
        return this;
    }

    /// <summary>Turns record parsing on or off.</summary>
    public WhoisClientBuilder WithRecordParsing(bool enabled)
    {
        _options.ParseRecords = enabled;
        return this;
    }

    /// <summary>Keeps every rule consulted in the verdict, not just the deciding one.</summary>
    public WhoisClientBuilder WithFullTrace(bool enabled = true)
    {
        _options.CollectFullTrace = enabled;
        return this;
    }

    /// <summary>Makes a failed lookup throw instead of returning an error result.</summary>
    public WhoisClientBuilder ThrowOnFailure(bool enabled = true)
    {
        _options.ThrowOnLookupFailure = enabled;
        return this;
    }

    /// <summary>Turns TLS certificate validation for RDAP on or off.</summary>
    /// <remarks>
    /// Off means every certificate is accepted, including a forged one. Only worth doing for a
    /// registry known to serve a broken chain, and worth reverting when they fix it.
    /// </remarks>
    public WhoisClientBuilder WithTlsValidation(bool enabled)
    {
        _options.ValidateTlsCertificates = enabled;
        return this;
    }

    /// <summary>Merges a JSON definitions file over the bundled table.</summary>
    public WhoisClientBuilder WithDefinitionsFile(string path)
    {
        _options.DefinitionsFilePath = path;
        return this;
    }

    /// <summary>Adds a definition source, applied after the bundled table.</summary>
    public WhoisClientBuilder AddDefinitionSource(IWhoisServerDefinitionSource source)
    {
        _options.AdditionalSources.Add(source ?? throw new ArgumentNullException(nameof(source)));
        return this;
    }

    /// <summary>Adds or replaces one suffix.</summary>
    /// <param name="tld">The suffix, with or without its leading dot.</param>
    /// <param name="uri"><c>socket://host[:port]</c> or an RDAP base URL.</param>
    /// <param name="available">Text the registry emits for an unregistered name.</param>
    /// <param name="premium">Text the registry emits for a premium or reserved name.</param>
    /// <param name="availableWhenEmpty">Whether a record-less reply means the name is free.</param>
    public WhoisClientBuilder AddServer(
        string tld,
        string uri,
        string? available = null,
        string? premium = null,
        bool availableWhenEmpty = false)
    {
        _options.AdditionalServers.Add(
            WhoisServerDefinition.Create(tld, uri, available, premium, availableWhenEmpty, source: "builder"));
        return this;
    }

    /// <summary>Uses only the configured sources, ignoring the table bundled with the package.</summary>
    public WhoisClientBuilder WithoutBundledDefinitions()
    {
        _options.UseBundledDefinitions = false;
        return this;
    }

    /// <summary>Adds a detection rule to the chain.</summary>
    public WhoisClientBuilder AddRule(IAvailabilityRule rule)
    {
        _extraRules.Add(rule ?? throw new ArgumentNullException(nameof(rule)));
        return this;
    }

    /// <summary>Adds a record parser, tried before the built-in ones.</summary>
    public WhoisClientBuilder AddRecordParser(IWhoisRecordParser parser)
    {
        _parsers.Add(parser ?? throw new ArgumentNullException(nameof(parser)));
        return this;
    }

    /// <summary>Supplies the suffix table directly.</summary>
    public WhoisClientBuilder WithRegistry(IWhoisServerRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        return this;
    }

    /// <summary>Supplies the transport stack directly — the seam tests use to stay offline.</summary>
    public WhoisClientBuilder WithTransportFactory(IWhoisTransportFactory factory)
    {
        _transportFactory = factory ?? throw new ArgumentNullException(nameof(factory));
        return this;
    }

    /// <summary>Supplies the analyzer directly.</summary>
    public WhoisClientBuilder WithAnalyzer(IAvailabilityAnalyzer analyzer)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        return this;
    }

    /// <summary>Supplies the <see cref="HttpClient"/> used for RDAP.</summary>
    public WhoisClientBuilder WithHttpClient(HttpClient httpClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        return this;
    }

    /// <summary>Turns on logging.</summary>
    public WhoisClientBuilder WithLogging(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        return this;
    }

    /// <summary>Builds the client.</summary>
    public WhoisClient Build()
    {
        _options.Validate();

        var registry = _registry ?? WhoisServerRegistry.FromOptions(_options);

        var analyzer = _analyzer;
        if (analyzer is null)
        {
            var rules = AvailabilityAnalyzer.CreateDefaultRules();
            foreach (var rule in _extraRules)
            {
                rules.Add(rule);
            }

            analyzer = new AvailabilityAnalyzer(rules, _options);
        }

        var transportFactory = _transportFactory
                               ?? new WhoisTransportFactory(_options, _cache, _httpClient, _loggerFactory);

        IWhoisRecordParser recordParser;
        if (_parsers.Count == 0)
        {
            recordParser = CompositeWhoisRecordParser.CreateDefault();
        }
        else
        {
            var all = new List<IWhoisRecordParser>(_parsers)
            {
                new RdapRecordParser(),
                new KeyValueWhoisRecordParser(),
            };

            recordParser = new CompositeWhoisRecordParser(all);
        }

        return new WhoisClient(
            _options,
            registry,
            transportFactory,
            analyzer,
            recordParser,
            new DomainNameParser(registry));
    }
}

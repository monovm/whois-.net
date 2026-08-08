using System;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Model;
using MonoVM.Whois.Transport.Decorators;

namespace MonoVM.Whois.Transport;

/// <summary>
/// Builds the transport stack for a registry: the right protocol at the bottom, the configured
/// cross-cutting behaviour layered over it.
/// </summary>
/// <remarks>
/// <para>
/// The stack, outermost first:
/// </para>
/// <list type="number">
///   <item><description>logging — sees the final outcome, cache hits included;</description></item>
///   <item><description>caching — short-circuits everything below it;</description></item>
///   <item><description>referral following — its own follow-up queries still get paced and retried;</description></item>
///   <item><description>rate limiting — one gate per host;</description></item>
///   <item><description>retry — closest to the wire, so it retries the network call and nothing else;</description></item>
///   <item><description>the protocol transport itself.</description></item>
/// </list>
/// <para>
/// Each layer is optional and configured by <see cref="WhoisOptions"/>. Two pipelines are built per
/// factory — one per protocol — and shared across every suffix, because none of the layers hold
/// per-suffix state.
/// </para>
/// </remarks>
public sealed class WhoisTransportFactory : IWhoisTransportFactory, IDisposable
{
    private readonly WhoisOptions _options;
    private readonly IWhoisResponseCache _cache;
    private readonly ILoggerFactory _loggerFactory;
    private readonly HostRateLimiter _rateLimiter;
    private readonly RdapHttpTransport _rdapTransport;

    private readonly Lazy<IWhoisTransport> _whois43Pipeline;
    private readonly Lazy<IWhoisTransport> _rdapPipeline;

    /// <summary>Creates the factory.</summary>
    /// <param name="options">What to build and how to configure it.</param>
    /// <param name="cache">Where replies are remembered; defaults to a bounded in-memory cache.</param>
    /// <param name="httpClient">Client for RDAP requests; supply one from <c>IHttpClientFactory</c> in a host.</param>
    /// <param name="loggerFactory">Optional logging.</param>
    /// <param name="rateLimiter">Optional shared pacing state.</param>
    public WhoisTransportFactory(
        WhoisOptions options,
        IWhoisResponseCache? cache = null,
        HttpClient? httpClient = null,
        ILoggerFactory? loggerFactory = null,
        HostRateLimiter? rateLimiter = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
        _rateLimiter = rateLimiter ?? HostRateLimiter.Shared;

        _cache = cache ?? (options.EnableCache
            ? (IWhoisResponseCache)new MemoryWhoisResponseCache()
            : NullWhoisResponseCache.Instance);

        _rdapTransport = new RdapHttpTransport(_options, httpClient, _loggerFactory.CreateLogger<RdapHttpTransport>());

        _whois43Pipeline = new Lazy<IWhoisTransport>(
            () => Compose(new Whois43Transport(_options, _loggerFactory.CreateLogger<Whois43Transport>()), followReferrals: true),
            isThreadSafe: true);

        _rdapPipeline = new Lazy<IWhoisTransport>(
            () => Compose(_rdapTransport, followReferrals: false),
            isThreadSafe: true);
    }

    /// <summary>The cache these pipelines share.</summary>
    public IWhoisResponseCache Cache => _cache;

    /// <inheritdoc />
    public IWhoisTransport Create(WhoisServerDefinition server)
    {
        if (server is null)
        {
            throw new ArgumentNullException(nameof(server));
        }

        return server.Protocol == WhoisProtocol.Rdap ? _rdapPipeline.Value : _whois43Pipeline.Value;
    }

    /// <inheritdoc />
    public void Dispose() => _rdapTransport.Dispose();

    private IWhoisTransport Compose(IWhoisTransport transport, bool followReferrals)
    {
        var logger = _loggerFactory.CreateLogger<WhoisTransportFactory>();

        if (_options.MaxRetryAttempts > 0)
        {
            transport = new RetryingWhoisTransport(transport, _options, logger);
        }

        if (_options.MinDelayBetweenQueriesPerHost > TimeSpan.Zero)
        {
            transport = new RateLimitingWhoisTransport(transport, _options, _rateLimiter);
        }

        // Only port 43 has referrals; RDAP endpoints answer in full or redirect at the HTTP layer.
        if (followReferrals && _options.FollowRegistrarReferrals && _options.MaxReferralDepth > 0)
        {
            transport = new ReferralFollowingWhoisTransport(transport, _options, logger);
        }

        if (_options.EnableCache)
        {
            transport = new CachingWhoisTransport(transport, _cache, _options);
        }

        if (_loggerFactory != NullLoggerFactory.Instance)
        {
            transport = new LoggingWhoisTransport(transport, logger);
        }

        return transport;
    }
}

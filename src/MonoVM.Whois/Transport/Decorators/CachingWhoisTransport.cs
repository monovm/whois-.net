using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Transport.Decorators;

/// <summary>
/// Serves a reply from the cache when one is still fresh.
/// </summary>
/// <remarks>
/// <para>
/// Only successful replies are cached. Caching a failure would turn one rate-limited answer into
/// several minutes of the same wrong non-answer, when a retry a second later might well have
/// worked.
/// </para>
/// <para>
/// Registration data changes on the scale of days, so even a short lifetime removes most of the
/// duplicate traffic a bulk check generates — the same suffix being asked about repeatedly is the
/// normal case, not the exception.
/// </para>
/// </remarks>
public sealed class CachingWhoisTransport : IWhoisTransport
{
    private readonly IWhoisTransport _inner;
    private readonly IWhoisResponseCache _cache;
    private readonly TimeSpan _lifetime;

    /// <summary>Creates the decorator.</summary>
    public CachingWhoisTransport(IWhoisTransport inner, IWhoisResponseCache cache, WhoisOptions options)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        _lifetime = options.CacheLifetime;
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        var key = BuildKey(query);

        if (_cache.TryGet(key, out var cached))
        {
            return cached.AsCached();
        }

        var response = await _inner.QueryAsync(query, cancellationToken).ConfigureAwait(false);
        _cache.Set(key, response, _lifetime);
        return response;
    }

    /// <summary>The cache key for a query: protocol, endpoint and the exact text sent.</summary>
    internal static string BuildKey(WhoisQuery query) => string.Format(
        CultureInfo.InvariantCulture,
        "{0}|{1}|{2}|{3}",
        query.Server.Protocol,
        query.Server.Host,
        query.Server.Port,
        query.QueryText.ToLowerInvariant());
}

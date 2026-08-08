using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Transport.Decorators;

/// <summary>
/// Keeps a minimum gap between consecutive queries to the same host.
/// </summary>
/// <remarks>
/// Registries rate-limit per client address, and a rate-limited reply is worse than a slow one: it
/// carries no verdict at all, so the lookup has to be repeated anyway. Pacing costs less than
/// retrying, and it is the difference between a bulk check that completes and one that gets the
/// caller's address blocked.
/// </remarks>
public sealed class RateLimitingWhoisTransport : IWhoisTransport
{
    private readonly IWhoisTransport _inner;
    private readonly HostRateLimiter _limiter;
    private readonly TimeSpan _minimumDelay;

    /// <summary>Creates the decorator.</summary>
    public RateLimitingWhoisTransport(IWhoisTransport inner, WhoisOptions options, HostRateLimiter? limiter = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        _minimumDelay = options.MinDelayBetweenQueriesPerHost;
        _limiter = limiter ?? HostRateLimiter.Shared;
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        if (_minimumDelay <= TimeSpan.Zero)
        {
            return await _inner.QueryAsync(query, cancellationToken).ConfigureAwait(false);
        }

        await _limiter.WaitAsync(query.Server.Host, _minimumDelay, cancellationToken).ConfigureAwait(false);
        return await _inner.QueryAsync(query, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Serialises access to each host and spaces the queries out.
/// </summary>
/// <remarks>
/// One gate per host, so a slow registry never holds up queries to a different one. The shared
/// instance exists because the limit being respected belongs to the client's IP address, not to any
/// single client object.
/// </remarks>
public sealed class HostRateLimiter : IDisposable
{
    private readonly ConcurrentDictionary<string, Gate> _gates =
        new ConcurrentDictionary<string, Gate>(StringComparer.OrdinalIgnoreCase);

    private readonly IClock _clock;

    /// <summary>Creates a limiter.</summary>
    public HostRateLimiter()
        : this(SystemClock.Instance)
    {
    }

    internal HostRateLimiter(IClock clock) => _clock = clock;

    /// <summary>The process-wide limiter.</summary>
    public static HostRateLimiter Shared { get; } = new HostRateLimiter();

    /// <summary>Waits until it is this caller's turn to query <paramref name="host"/>.</summary>
    public async Task WaitAsync(string host, TimeSpan minimumDelay, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(host) || minimumDelay <= TimeSpan.Zero)
        {
            return;
        }

        var gate = _gates.GetOrAdd(host, _ => new Gate());

        await gate.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = _clock.UtcNow;
            var earliest = gate.LastQueryAt + minimumDelay;

            if (earliest > now)
            {
                await Task.Delay(earliest - now, cancellationToken).ConfigureAwait(false);
                now = _clock.UtcNow;
            }

            gate.LastQueryAt = now;
        }
        finally
        {
            gate.Semaphore.Release();
        }
    }

    /// <summary>Forgets the pacing state for every host.</summary>
    public void Reset()
    {
        foreach (var gate in _gates.Values)
        {
            gate.LastQueryAt = DateTimeOffset.MinValue;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var gate in _gates.Values)
        {
            gate.Semaphore.Dispose();
        }

        _gates.Clear();
    }

    private sealed class Gate
    {
        public SemaphoreSlim Semaphore { get; } = new SemaphoreSlim(1, 1);

        public DateTimeOffset LastQueryAt { get; set; } = DateTimeOffset.MinValue;
    }
}

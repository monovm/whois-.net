using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Transport.Decorators;

/// <summary>
/// Retries a lookup that failed for a reason that might not repeat.
/// </summary>
/// <remarks>
/// <para>
/// Only transient failures are retried: a connection that could not be made, and a server that
/// refused with a rate limit or a 5xx. A well-formed "no such domain" is not a failure, and a
/// blocked client will still be blocked in five hundred milliseconds.
/// </para>
/// <para>
/// A decorator rather than a feature of each transport: retrying is the same policy whether the
/// query went out over port 43 or over HTTPS, and neither transport should have to know about it.
/// </para>
/// </remarks>
public sealed class RetryingWhoisTransport : IWhoisTransport
{
    private readonly IWhoisTransport _inner;
    private readonly int _maxAttempts;
    private readonly TimeSpan _baseDelay;
    private readonly ILogger _logger;

    /// <summary>Creates the decorator.</summary>
    public RetryingWhoisTransport(IWhoisTransport inner, WhoisOptions options, ILogger? logger = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        _maxAttempts = Math.Max(0, options.MaxRetryAttempts) + 1;
        _baseDelay = options.RetryDelay;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        var delay = _baseDelay;

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await _inner.QueryAsync(query, cancellationToken).ConfigureAwait(false);
            }
            catch (WhoisException exception) when (attempt < _maxAttempts && IsWorthRetrying(exception))
            {
                _logger.LogDebug(
                    exception,
                    "Attempt {Attempt} of {MaxAttempts} for {Domain} failed; retrying in {Delay}ms.",
                    attempt, _maxAttempts, query.Domain.Ascii, delay.TotalMilliseconds);

                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    delay = TimeSpan.FromTicks(delay.Ticks * 2);
                }
            }
        }
    }

    private static bool IsWorthRetrying(WhoisException exception) => exception switch
    {
        // A connection that could not be made, or a read that timed out, may well work next time.
        WhoisConnectionException => true,

        // A rate limit or a 5xx may clear; a blocked client or a retired endpoint will not.
        WhoisServerException server => server.IsTransient,

        // An empty reply is usually a half-open connection rather than a real answer.
        EmptyWhoisResponseException => true,

        _ => false,
    };
}

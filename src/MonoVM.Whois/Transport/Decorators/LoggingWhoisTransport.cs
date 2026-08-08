using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Transport.Decorators;

/// <summary>Records what was asked, of whom, and how it went.</summary>
/// <remarks>
/// Kept as a decorator so that neither transport carries logging concerns, and so that a caller who
/// wants none pays for none.
/// </remarks>
public sealed class LoggingWhoisTransport : IWhoisTransport
{
    private readonly IWhoisTransport _inner;
    private readonly ILogger _logger;

    /// <summary>Creates the decorator.</summary>
    public LoggingWhoisTransport(IWhoisTransport inner, ILogger logger)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var response = await _inner.QueryAsync(query, cancellationToken).ConfigureAwait(false);

            stopwatch.Stop();
            _logger.LogInformation(
                "WHOIS {Domain} via {Protocol} {Server} -> {Bytes} bytes in {Elapsed}ms{Cached}.",
                query.Domain.Unicode,
                response.Protocol,
                response.Server,
                response.Text.Length,
                stopwatch.ElapsedMilliseconds,
                response.FromCache ? " (cached)" : string.Empty);

            return response;
        }
        catch (WhoisException exception)
        {
            stopwatch.Stop();
            _logger.LogWarning(
                exception,
                "WHOIS {Domain} via {Server} failed after {Elapsed}ms: {Code}.",
                query.Domain.Unicode, query.Server.Host, stopwatch.ElapsedMilliseconds, exception.Code);

            throw;
        }
    }
}

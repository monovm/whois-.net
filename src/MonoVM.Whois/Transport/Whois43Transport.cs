using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Transport;

/// <summary>
/// Speaks the WHOIS protocol of RFC 3912: connect, send one line, read until the server hangs up.
/// </summary>
/// <remarks>
/// The protocol has no framing, no status codes and no content type, which is why so much of this
/// library is about interpreting what comes back. This class does none of that interpreting — it
/// returns the bytes as text and nothing more.
/// </remarks>
public sealed class Whois43Transport : IWhoisTransport
{
    private const int ReadBufferSize = 8 * 1024;
    private const int MaxResponseBytes = 4 * 1024 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly WhoisOptions _options;
    private readonly ILogger _logger;

    /// <summary>Creates the transport.</summary>
    public Whois43Transport(WhoisOptions options, ILogger<Whois43Transport>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        if (query.Server.Protocol != WhoisProtocol.Whois43)
        {
            throw new WhoisDefinitionException(
                $"{nameof(Whois43Transport)} cannot serve {query.Server.Uri}, which is not a port-43 endpoint.");
        }

        var host = query.Server.Host;
        var port = query.Server.Port;
        var stopwatch = Stopwatch.StartNew();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Whois43Timeout);

        using var client = new TcpClient { NoDelay = true };

        // TcpClient has no cancellable ConnectAsync on every target framework this package supports.
        // Closing the socket from the token's callback aborts whatever is in flight, which is the
        // portable way to make the whole exchange respect a deadline.
        using var abort = timeout.Token.Register(static state => CloseQuietly((TcpClient)state!), client);

        byte[] payload;
        try
        {
            await client.ConnectAsync(host, port).ConfigureAwait(false);

            using var stream = client.GetStream();

            var request = Encoding.UTF8.GetBytes(query.QueryText + "\r\n");
            await stream.WriteAsync(request, 0, request.Length, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

            payload = await ReadToEndAsync(stream, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var timedOut = timeout.IsCancellationRequested;
            _logger.LogDebug(
                exception,
                "WHOIS query for {Domain} to {Host}:{Port} failed after {Elapsed}ms.",
                query.Domain.Ascii, host, port, stopwatch.ElapsedMilliseconds);

            throw new WhoisConnectionException(
                timedOut
                    ? $"The WHOIS server {host}:{port} did not answer within {_options.Whois43Timeout.TotalSeconds:0.#}s."
                    : $"The WHOIS server {host}:{port} could not be reached: {exception.Message}",
                host,
                exception)
            {
                IsTimeout = timedOut,
            };
        }

        stopwatch.Stop();

        var text = Decode(payload);
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new EmptyWhoisResponseException(
                $"The WHOIS server {host} answered nothing for {query.Domain.Unicode}.", host);
        }

        _logger.LogDebug(
            "WHOIS query for {Domain} to {Host}:{Port} returned {Bytes} bytes in {Elapsed}ms.",
            query.Domain.Ascii, host, port, payload.Length, stopwatch.ElapsedMilliseconds);

        return new WhoisResponse(query.Domain, text, WhoisProtocol.Whois43, host, stopwatch.Elapsed);
    }

    private static async Task<byte[]> ReadToEndAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(ReadBufferSize);
        var chunk = new byte[ReadBufferSize];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                break;
            }

            buffer.Write(chunk, 0, read);

            // A registry has no reason to send megabytes, and an unbounded read is a way to be
            // held open indefinitely by a misbehaving or hostile server.
            if (buffer.Length >= MaxResponseBytes)
            {
                break;
            }
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Decodes a reply, preferring UTF-8 and falling back to Latin-1.
    /// </summary>
    /// <remarks>
    /// The protocol specifies no encoding at all. Most registries send UTF-8; a few older ones send
    /// Latin-1, and decoding those as UTF-8 turns accented registrant names into replacement
    /// characters. Trying strict UTF-8 first and falling back gets both right.
    /// </remarks>
    internal static string Decode(byte[] payload)
    {
        if (payload.Length == 0)
        {
            return string.Empty;
        }

        try
        {
            return StrictUtf8.GetString(payload);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.GetEncoding(28591).GetString(payload);
        }
    }

    private static bool IsTransportFailure(Exception exception)
        => exception is SocketException
           || exception is IOException
           || exception is ObjectDisposedException
           || exception is InvalidOperationException
           || exception is OperationCanceledException;

    private static void CloseQuietly(TcpClient client)
    {
        try
        {
            client.Close();
        }
        catch (Exception)
        {
            // The socket is being torn down; nothing here can improve the outcome.
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
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
/// Queries a Registration Data Access Protocol endpoint — WHOIS's structured replacement.
/// </summary>
/// <remarks>
/// <para>
/// RDAP has what WHOIS lacks: status codes and a schema. A name that does not exist gets an
/// unambiguous <c>404</c>, which is worth far more than guessing at prose. This class keeps that
/// distinction intact: a 404 body is returned as the answer it is, while a refusal (401, 403, 429,
/// or any 5xx) is raised, because a refusal is not a verdict.
/// </para>
/// <para>
/// The <see cref="HttpClient"/> can be supplied by the caller, which is how this plays with
/// <c>IHttpClientFactory</c>, Polly handlers and test doubles.
/// </para>
/// </remarks>
public sealed class RdapHttpTransport : IWhoisTransport, IDisposable
{
    private static readonly HashSet<int> RefusalStatuses = new HashSet<int> { 401, 403, 405, 406, 409, 429 };

    private static readonly Lazy<HttpClient> SharedValidating =
        new Lazy<HttpClient>(() => CreateClient(validateCertificates: true), isThreadSafe: true);

    private static readonly Lazy<HttpClient> SharedPermissive =
        new Lazy<HttpClient>(() => CreateClient(validateCertificates: false), isThreadSafe: true);

    private readonly WhoisOptions _options;
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    /// <summary>Creates the transport.</summary>
    /// <param name="options">Timeouts, TLS policy and user agent.</param>
    /// <param name="httpClient">
    /// The client to send with. When omitted, a process-wide client matching the TLS policy is used.
    /// </param>
    /// <param name="logger">Optional logger.</param>
    public RdapHttpTransport(WhoisOptions options, HttpClient? httpClient = null, ILogger<RdapHttpTransport>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = (ILogger?)logger ?? NullLogger.Instance;

        if (httpClient is not null)
        {
            _httpClient = httpClient;
            _ownsClient = false;
        }
        else
        {
            _httpClient = _options.ValidateTlsCertificates ? SharedValidating.Value : SharedPermissive.Value;
            _ownsClient = false;
        }
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        if (query.Server.Protocol != WhoisProtocol.Rdap)
        {
            throw new WhoisDefinitionException(
                $"{nameof(RdapHttpTransport)} cannot serve {query.Server.Uri}, which is not an HTTP endpoint.");
        }

        // The definition holds the base URL; the query is appended verbatim. A URL always carries
        // the punycode form, whatever the caller typed.
        var url = query.Server.Uri + Uri.EscapeDataString(query.Domain.Ascii);
        var stopwatch = Stopwatch.StartNew();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.RdapTimeout);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/rdap+json");
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.Clear();
        request.Headers.UserAgent.Add(ProductInfoHeaderValue.Parse(SanitizeUserAgent(_options.UserAgent)));

        HttpResponseMessage response;
        string body;

        try
        {
            response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token)
                .ConfigureAwait(false);
            body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is HttpRequestException || exception is OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var timedOut = timeout.IsCancellationRequested;
            throw new WhoisConnectionException(
                timedOut
                    ? $"The RDAP service at {query.Server.Host} did not answer within {_options.RdapTimeout.TotalSeconds:0.#}s."
                    : $"The RDAP service at {query.Server.Host} could not be reached: {exception.Message}",
                query.Server.Host,
                exception)
            {
                IsTimeout = timedOut,
            };
        }

        using (response)
        {
            stopwatch.Stop();
            var status = (int)response.StatusCode;

            // 404 is how RDAP says "no such domain", so its body is the answer. A refusal or a
            // server fault is not an answer at all, and handing its HTML to the analyzer is how a
            // registered domain ends up reported as free.
            if (RefusalStatuses.Contains(status) || status >= 500)
            {
                throw new WhoisServerException(
                    $"The RDAP service at {query.Server.Host} refused the query: HTTP {status} {response.ReasonPhrase}.",
                    query.Server.Host,
                    status)
                {
                    IsTransient = status == 429 || status >= 500,
                };
            }

            if (string.IsNullOrWhiteSpace(body))
            {
                if (status == 404)
                {
                    // An empty 404 still carries its verdict in the status line.
                    body = "{\"errorCode\": 404, \"title\": \"Not Found\"}";
                }
                else
                {
                    throw new EmptyWhoisResponseException(
                        $"The RDAP service at {query.Server.Host} answered HTTP {status} with an empty body.",
                        query.Server.Host);
                }
            }

            _logger.LogDebug(
                "RDAP query for {Domain} to {Url} returned HTTP {Status} in {Elapsed}ms.",
                query.Domain.Ascii, url, status, stopwatch.ElapsedMilliseconds);

            return new WhoisResponse(
                query.Domain, body, WhoisProtocol.Rdap, query.Server.Uri, stopwatch.Elapsed, status);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }
    }

    private static string SanitizeUserAgent(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return "MonoVM.Whois";
        }

        // ProductInfoHeaderValue.Parse is strict; a value it cannot read must not break a lookup.
        try
        {
            ProductInfoHeaderValue.Parse(userAgent);
            return userAgent!;
        }
        catch (FormatException)
        {
            return "MonoVM.Whois";
        }
    }

    private static HttpClient CreateClient(bool validateCertificates)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
        };

        if (!validateCertificates)
        {
            try
            {
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            }
            catch (NotSupportedException)
            {
                // Some platforms refuse to let the callback be replaced — PlatformNotSupportedException
                // derives from this one. Validation then stays on, which is the safe way to fail.
            }
        }

        return new HttpClient(handler, disposeHandler: true)
        {
            // Cancellation is driven per request from the caller's token, so the client-wide
            // timeout must not fire first and turn a deadline into an opaque TaskCanceledException.
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }
}

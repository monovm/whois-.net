using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
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
/// Follows a thin registry's pointer to the registrar that holds the full record.
/// </summary>
/// <remarks>
/// <para>
/// Verisign and the other thin registries publish only the registrar name, the status codes and
/// the dates; everything else lives on the registrar's own server, named in the reply as
/// <c>Registrar WHOIS Server:</c>. Following that pointer is the difference between knowing a
/// domain is taken and knowing anything about it.
/// </para>
/// <para>
/// The registry's own reply stays the primary one. A registrar server asked about a domain it does
/// not sponsor may answer "No match", and letting that decide availability would report a
/// registered domain as free — so referral bodies are attached as
/// <see cref="WhoisResponse.Referrals"/> and used only to enrich the parsed record.
/// </para>
/// </remarks>
public sealed class ReferralFollowingWhoisTransport : IWhoisTransport
{
    private static readonly Regex ReferralPattern = new Regex(
        @"^[ \t]*(?:registrar\s+whois\s+server|whois\s+server|refer|whois)[\s._-]*:[ \t]*(?<host>[a-z0-9.\-]+)[ \t]*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline);

    private readonly IWhoisTransport _inner;
    private readonly int _maxDepth;
    private readonly ILogger _logger;

    /// <summary>Creates the decorator.</summary>
    public ReferralFollowingWhoisTransport(IWhoisTransport inner, WhoisOptions options, ILogger? logger = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        _maxDepth = options.FollowRegistrarReferrals ? Math.Max(0, options.MaxReferralDepth) : 0;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public async Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        var response = await _inner.QueryAsync(query, cancellationToken).ConfigureAwait(false);

        if (_maxDepth == 0 || response.Protocol != WhoisProtocol.Whois43)
        {
            return response;
        }

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { query.Server.Host };
        var referrals = new List<WhoisResponse>();
        var current = response;

        for (var depth = 0; depth < _maxDepth; depth++)
        {
            var host = FindReferral(current.Text, visited);
            if (host is null)
            {
                break;
            }

            visited.Add(host);

            WhoisServerDefinition referralServer;
            try
            {
                referralServer = WhoisServerDefinition.Create(
                    query.Server.Tld,
                    WhoisServerDefinition.SocketScheme + host,
                    source: "referral");
            }
            catch (WhoisDefinitionException)
            {
                break;
            }

            try
            {
                current = await _inner.QueryAsync(query.RedirectTo(referralServer), cancellationToken)
                    .ConfigureAwait(false);
                referrals.Add(current);
            }
            catch (WhoisException exception)
            {
                // The registry already answered. A registrar server that will not talk to us costs
                // detail, not correctness, so it must never turn a good lookup into a failure.
                _logger.LogDebug(
                    exception,
                    "Referral to {Host} for {Domain} failed; keeping the registry reply.",
                    host, query.Domain.Ascii);
                break;
            }
        }

        return referrals.Count == 0 ? response : response.WithReferrals(referrals);
    }

    /// <summary>Finds the next registrar WHOIS server named in <paramref name="text"/>.</summary>
    internal static string? FindReferral(string text, ICollection<string> visited)
    {
        foreach (Match match in ReferralPattern.Matches(text))
        {
            var host = match.Groups["host"].Value.Trim().TrimEnd('.').ToLowerInvariant();

            if (host.Length == 0 || host.IndexOf('.') < 0 || visited.Contains(host))
            {
                continue;
            }

            // Some registries print the string "not applicable" or a URL in this field.
            if (host.StartsWith("http", StringComparison.Ordinal) || host.Contains("/"))
            {
                continue;
            }

            return host;
        }

        return null;
    }
}

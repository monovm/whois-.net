using System;
using System.Globalization;
using MonoVM.Whois.Exceptions;

namespace MonoVM.Whois.Model;

/// <summary>
/// Everything the library knows about the registry that serves one suffix: where to ask, and how
/// that particular registry words its answers.
/// </summary>
/// <remarks>
/// Instances are immutable. They are produced by an
/// <see cref="Abstractions.IWhoisServerDefinitionSource"/> and handed out by an
/// <see cref="Abstractions.IWhoisServerRegistry"/>.
/// </remarks>
public sealed class WhoisServerDefinition
{
    /// <summary>The default TCP port of the WHOIS protocol (RFC 3912).</summary>
    public const int DefaultWhoisPort = 43;

    /// <summary>The URI scheme marking a port-43 WHOIS server in the definition files.</summary>
    public const string SocketScheme = "socket://";

    private WhoisServerDefinition(
        string tld,
        string uri,
        WhoisProtocol protocol,
        string host,
        int port,
        string? availableMatch,
        string? premiumMatch,
        bool availableWhenEmpty,
        string? comment,
        string? source)
    {
        Tld = tld;
        Uri = uri;
        Protocol = protocol;
        Host = host;
        Port = port;
        AvailableMatch = string.IsNullOrWhiteSpace(availableMatch) ? null : availableMatch!.Trim();
        PremiumMatch = string.IsNullOrWhiteSpace(premiumMatch) ? null : premiumMatch!.Trim();
        AvailableWhenEmpty = availableWhenEmpty;
        Comment = string.IsNullOrWhiteSpace(comment) ? null : comment!.Trim();
        Source = source;
    }

    /// <summary>The suffix this entry serves, punycode, lower case, with a leading dot.</summary>
    public string Tld { get; }

    /// <summary>The raw endpoint as written in the definition file.</summary>
    public string Uri { get; }

    /// <summary>Which protocol <see cref="Uri"/> speaks.</summary>
    public WhoisProtocol Protocol { get; }

    /// <summary>Host name for a port-43 server; the full base URL for an RDAP endpoint.</summary>
    public string Host { get; }

    /// <summary>TCP port for a port-43 server; 443 for RDAP.</summary>
    public int Port { get; }

    /// <summary>Text this registry emits when a name is unregistered, if it has a distinctive one.</summary>
    public string? AvailableMatch { get; }

    /// <summary>Text this registry emits for a premium or reserved name, if any.</summary>
    public string? PremiumMatch { get; }

    /// <summary>
    /// True for the handful of registries that answer an unregistered name with nothing but their
    /// banner. Only for those may an absent record be read as availability.
    /// </summary>
    public bool AvailableWhenEmpty { get; }

    /// <summary>Free-form note explaining a non-obvious entry; ignored by the lookup itself.</summary>
    public string? Comment { get; }

    /// <summary>Name of the definition source this entry came from, for diagnostics.</summary>
    public string? Source { get; }

    /// <summary>True when the entry points at a port-43 WHOIS server.</summary>
    public bool IsWhois43 => Protocol == WhoisProtocol.Whois43;

    /// <summary>
    /// Builds a definition, deriving the protocol, host and port from <paramref name="uri"/>.
    /// </summary>
    /// <param name="tld">Suffix served, with or without a leading dot.</param>
    /// <param name="uri"><c>socket://host[:port]</c> for WHOIS port 43, or an <c>https://…/domain/</c> RDAP base URL.</param>
    /// <param name="available">Text the registry emits for an unregistered name.</param>
    /// <param name="premium">Text the registry emits for a premium or reserved name.</param>
    /// <param name="availableWhenEmpty">Whether a record-less reply means the name is free.</param>
    /// <param name="comment">Free-form note.</param>
    /// <param name="source">Name of the providing definition source.</param>
    /// <exception cref="WhoisDefinitionException">The suffix or the URI is unusable.</exception>
    public static WhoisServerDefinition Create(
        string tld,
        string uri,
        string? available = null,
        string? premium = null,
        bool availableWhenEmpty = false,
        string? comment = null,
        string? source = null)
    {
        var suffix = DomainName.NormalizeSuffix(tld);
        if (suffix.Length == 0)
        {
            throw new WhoisDefinitionException("A server definition must name the suffix it serves.");
        }

        suffix = Internal.DomainNameNormalizer.ToAscii(suffix);

        if (string.IsNullOrWhiteSpace(uri))
        {
            throw new WhoisDefinitionException($"No endpoint configured for {suffix}.");
        }

        var endpoint = uri.Trim();

        if (endpoint.StartsWith(SocketScheme, StringComparison.OrdinalIgnoreCase))
        {
            var (host, port) = SplitSocketTarget(endpoint.Substring(SocketScheme.Length));
            if (host.Length == 0)
            {
                throw new WhoisDefinitionException($"The endpoint '{endpoint}' for {suffix} names no host.");
            }

            return new WhoisServerDefinition(
                suffix, endpoint, WhoisProtocol.Whois43, host, port,
                available, premium, availableWhenEmpty, comment, source);
        }

        if (endpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!System.Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed))
            {
                throw new WhoisDefinitionException($"The endpoint '{endpoint}' for {suffix} is not a valid URL.");
            }

            return new WhoisServerDefinition(
                suffix, endpoint, WhoisProtocol.Rdap, parsed.Host, parsed.Port,
                available, premium, availableWhenEmpty, comment, source);
        }

        throw new WhoisDefinitionException(
            $"The endpoint '{endpoint}' for {suffix} must start with '{SocketScheme}', 'http://' or 'https://'.");
    }

    /// <summary>Returns a copy of this entry tagged with the name of its source.</summary>
    internal WhoisServerDefinition WithSource(string source)
        => new WhoisServerDefinition(
            Tld, Uri, Protocol, Host, Port, AvailableMatch, PremiumMatch, AvailableWhenEmpty, Comment, source);

    private static (string Host, int Port) SplitSocketTarget(string target)
    {
        var host = target.Trim().Trim('/');
        var port = DefaultWhoisPort;

        var colon = host.IndexOf(':');
        if (colon > 0)
        {
            var portText = host.Substring(colon + 1);
            host = host.Substring(0, colon);
            if (int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) &&
                parsed > 0 && parsed <= 65535)
            {
                port = parsed;
            }
        }

        return (host, port);
    }

    /// <inheritdoc />
    public override string ToString() => $"{Tld} -> {Uri}";
}

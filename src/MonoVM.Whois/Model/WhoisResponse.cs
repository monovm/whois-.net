using System;
using System.Collections.Generic;

namespace MonoVM.Whois.Model;

/// <summary>The raw answer from one registry, before any interpretation.</summary>
public sealed class WhoisResponse
{
    private static readonly IReadOnlyList<WhoisResponse> NoReferrals = Array.Empty<WhoisResponse>();

    /// <summary>Creates a response.</summary>
    public WhoisResponse(
        DomainName domain,
        string text,
        WhoisProtocol protocol,
        string server,
        TimeSpan duration,
        int? httpStatusCode = null,
        bool fromCache = false,
        IReadOnlyList<WhoisResponse>? referrals = null)
    {
        Domain = domain ?? throw new ArgumentNullException(nameof(domain));
        Text = text ?? string.Empty;
        Protocol = protocol;
        Server = server ?? string.Empty;
        Duration = duration;
        HttpStatusCode = httpStatusCode;
        FromCache = fromCache;
        Referrals = referrals ?? NoReferrals;
    }

    /// <summary>The domain that was asked about.</summary>
    public DomainName Domain { get; }

    /// <summary>The verbatim reply: WHOIS text, or the RDAP JSON body.</summary>
    public string Text { get; }

    /// <summary>Which protocol produced <see cref="Text"/>.</summary>
    public WhoisProtocol Protocol { get; }

    /// <summary>The host or URL that answered.</summary>
    public string Server { get; }

    /// <summary>How long the exchange took.</summary>
    public TimeSpan Duration { get; }

    /// <summary>HTTP status of an RDAP reply; <see langword="null"/> for port 43.</summary>
    public int? HttpStatusCode { get; }

    /// <summary>True when the text was served from the response cache rather than the network.</summary>
    public bool FromCache { get; }

    /// <summary>
    /// Extra replies gathered by following referrals, in the order they were fetched.
    /// </summary>
    /// <remarks>
    /// <see cref="Text"/> always stays the registry's own reply, because that is the only one whose
    /// wording the availability rules are calibrated against — a registrar's server answering "no
    /// match" for a domain it does not sponsor must never be read as the domain being free.
    /// Referral bodies are used to fill in record detail, never to decide availability.
    /// </remarks>
    public IReadOnlyList<WhoisResponse> Referrals { get; }

    /// <summary>True when the server answered with nothing but whitespace.</summary>
    public bool IsEmpty => string.IsNullOrWhiteSpace(Text);

    /// <summary>Returns a copy of this response marked as coming from the cache.</summary>
    public WhoisResponse AsCached()
        => FromCache ? this : new WhoisResponse(Domain, Text, Protocol, Server, Duration, HttpStatusCode, true, Referrals);

    /// <summary>Returns a copy of this response carrying <paramref name="referrals"/>.</summary>
    public WhoisResponse WithReferrals(IReadOnlyList<WhoisResponse> referrals)
        => new WhoisResponse(Domain, Text, Protocol, Server, Duration, HttpStatusCode, FromCache, referrals);

    /// <inheritdoc />
    public override string ToString() => $"{Domain} @ {Server} ({Text.Length} chars)";
}

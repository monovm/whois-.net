using System;

namespace MonoVM.Whois.Model;

/// <summary>One question to put to one registry.</summary>
/// <remarks>
/// The query text is kept separate from the domain because the two are not always the same string:
/// most registries want the punycode form of an internationalised name, DENIC wants the Unicode
/// form, and a referral follow-up may need a registrar-specific query syntax.
/// </remarks>
public sealed class WhoisQuery
{
    /// <summary>Creates a query.</summary>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    public WhoisQuery(DomainName domain, WhoisServerDefinition server, string queryText)
    {
        Domain = domain ?? throw new ArgumentNullException(nameof(domain));
        Server = server ?? throw new ArgumentNullException(nameof(server));
        QueryText = queryText ?? throw new ArgumentNullException(nameof(queryText));
    }

    /// <summary>The domain being looked up.</summary>
    public DomainName Domain { get; }

    /// <summary>The registry to ask.</summary>
    public WhoisServerDefinition Server { get; }

    /// <summary>The exact string to put on the wire, or to append to the RDAP base URL.</summary>
    public string QueryText { get; }

    /// <summary>Returns the same query aimed at a different server, e.g. when following a referral.</summary>
    public WhoisQuery RedirectTo(WhoisServerDefinition server) => new WhoisQuery(Domain, server, QueryText);

    /// <inheritdoc />
    public override string ToString() => $"{QueryText} @ {Server.Host}";
}

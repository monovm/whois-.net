using System;
using System.Collections.Generic;
using System.Linq;

namespace MonoVM.Whois.Model;

/// <summary>
/// A registration record, parsed out of a WHOIS text reply or an RDAP JSON document.
/// </summary>
/// <remarks>
/// <para>
/// Registries agree on very little beyond "key, colon, value", so every property here is nullable
/// or empty-by-default. Nothing is invented: a property is populated only when the reply actually
/// carried it under a recognised key.
/// </para>
/// <para>
/// <see cref="Fields"/> keeps every key/value pair the reply contained, including the ones with no
/// strongly typed home, so nothing is lost to the parser's opinion of what matters.
/// </para>
/// </remarks>
public sealed class WhoisRecord
{
    /// <summary>A record with nothing in it.</summary>
    public static readonly WhoisRecord Empty = new WhoisRecord();

    /// <summary>The domain name as the registry spells it.</summary>
    public string? DomainName { get; init; }

    /// <summary>The registry's own identifier for the registration (ICANN "Registry Domain ID").</summary>
    public string? RegistryDomainId { get; init; }

    /// <summary>Name of the sponsoring registrar.</summary>
    public string? Registrar { get; init; }

    /// <summary>The registrar's IANA identifier.</summary>
    public string? RegistrarIanaId { get; init; }

    /// <summary>The registrar's own WHOIS server, if the registry referred to one.</summary>
    public string? RegistrarWhoisServer { get; init; }

    /// <summary>The registrar's web site.</summary>
    public string? RegistrarUrl { get; init; }

    /// <summary>Abuse contact email published by the registrar.</summary>
    public string? RegistrarAbuseEmail { get; init; }

    /// <summary>Abuse contact phone published by the registrar.</summary>
    public string? RegistrarAbusePhone { get; init; }

    /// <summary>When the domain was first registered.</summary>
    public DateTimeOffset? CreatedOn { get; init; }

    /// <summary>When the record was last changed.</summary>
    public DateTimeOffset? UpdatedOn { get; init; }

    /// <summary>When the registration lapses unless renewed.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Authoritative name servers, lower-cased and de-duplicated.</summary>
    public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();

    /// <summary>EPP status codes and free-form status strings, as written.</summary>
    public IReadOnlyList<string> Statuses { get; init; } = Array.Empty<string>();

    /// <summary>Whether the zone is signed, when the registry says so.</summary>
    public bool? DnsSecEnabled { get; init; }

    /// <summary>The party the domain is registered to.</summary>
    public DomainContact? Registrant { get; init; }

    /// <summary>Administrative contact.</summary>
    public DomainContact? Administrative { get; init; }

    /// <summary>Technical contact.</summary>
    public DomainContact? Technical { get; init; }

    /// <summary>Billing contact.</summary>
    public DomainContact? Billing { get; init; }

    /// <summary>
    /// Every key/value pair found, keyed case-insensitively by the label as the registry wrote it.
    /// A key that appeared more than once keeps all of its values, in order.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Fields { get; init; }
        = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The reply this record was parsed from.</summary>
    public string RawText { get; init; } = string.Empty;

    /// <summary>True when the parser recognised nothing at all.</summary>
    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(DomainName) &&
        string.IsNullOrWhiteSpace(Registrar) &&
        CreatedOn is null &&
        ExpiresOn is null &&
        NameServers.Count == 0 &&
        Statuses.Count == 0 &&
        Fields.Count == 0;

    /// <summary>How long until <see cref="ExpiresOn"/>, or <see langword="null"/> if unknown.</summary>
    public TimeSpan? TimeUntilExpiry(DateTimeOffset? now = null)
        => ExpiresOn is null ? null : ExpiresOn.Value - (now ?? DateTimeOffset.UtcNow);

    /// <summary>Returns the first value recorded under <paramref name="key"/>, if any.</summary>
    public string? Field(string key)
        => Fields.TryGetValue(key, out var values) && values.Count > 0 ? values[0] : null;

    /// <summary>Returns every value recorded under <paramref name="key"/>.</summary>
    public IReadOnlyList<string> FieldValues(string key)
        => Fields.TryGetValue(key, out var values) ? values : Array.Empty<string>();

    /// <summary>True when any status code contains <paramref name="fragment"/>, ignoring case.</summary>
    public bool HasStatus(string fragment)
        => Statuses.Any(status => status.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0);

    /// <inheritdoc />
    public override string ToString()
        => DomainName is null ? "(empty record)" : $"{DomainName} ({Registrar ?? "unknown registrar"})";
}

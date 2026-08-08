using System.Collections.Generic;
using MonoVM.Whois.Internal;

namespace MonoVM.Whois.Model;

/// <summary>One of the parties recorded against a domain.</summary>
/// <remarks>
/// Most registries redact most of these under GDPR, so expect nearly every property to be
/// <see langword="null"/> for a generic TLD. The type is still worth having: the fields that do
/// survive redaction (organisation and country, usually) are the ones people query for.
/// </remarks>
public sealed class DomainContact
{
    /// <summary>A contact with nothing in it.</summary>
    public static readonly DomainContact Empty = new DomainContact();

    /// <summary>Which role this contact plays.</summary>
    public DomainContactType Type { get; init; } = DomainContactType.Unknown;

    /// <summary>Personal or role name.</summary>
    public string? Name { get; init; }

    /// <summary>Organisation the contact belongs to.</summary>
    public string? Organization { get; init; }

    /// <summary>Email address, or the registrar's redaction proxy.</summary>
    public string? Email { get; init; }

    /// <summary>Voice telephone number.</summary>
    public string? Phone { get; init; }

    /// <summary>Fax number.</summary>
    public string? Fax { get; init; }

    /// <summary>Street address lines, in the order the registry listed them.</summary>
    public IReadOnlyList<string> Street { get; init; } = System.Array.Empty<string>();

    /// <summary>City.</summary>
    public string? City { get; init; }

    /// <summary>State, province or region.</summary>
    public string? StateOrProvince { get; init; }

    /// <summary>Postal or ZIP code.</summary>
    public string? PostalCode { get; init; }

    /// <summary>Country, as the registry wrote it — usually an ISO 3166-1 alpha-2 code.</summary>
    public string? Country { get; init; }

    /// <summary>True when the registry supplied nothing for this contact.</summary>
    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(Name) &&
        string.IsNullOrWhiteSpace(Organization) &&
        string.IsNullOrWhiteSpace(Email) &&
        string.IsNullOrWhiteSpace(Phone) &&
        string.IsNullOrWhiteSpace(Fax) &&
        Street.Count == 0 &&
        string.IsNullOrWhiteSpace(City) &&
        string.IsNullOrWhiteSpace(StateOrProvince) &&
        string.IsNullOrWhiteSpace(PostalCode) &&
        string.IsNullOrWhiteSpace(Country);

    /// <inheritdoc />
    public override string ToString()
        => StringHelpers.JoinNonEmpty(", ", new[] { Name, Organization, Email, Country });
}

/// <summary>The role a <see cref="DomainContact"/> plays for a domain.</summary>
public enum DomainContactType
{
    /// <summary>Role not stated by the registry.</summary>
    Unknown = 0,

    /// <summary>The party the domain is registered to.</summary>
    Registrant = 1,

    /// <summary>Administrative contact.</summary>
    Administrative = 2,

    /// <summary>Technical contact.</summary>
    Technical = 3,

    /// <summary>Billing contact.</summary>
    Billing = 4,
}

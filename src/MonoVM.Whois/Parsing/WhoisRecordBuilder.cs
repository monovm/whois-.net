using System;
using System.Collections.Generic;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Parsing;

/// <summary>Accumulates the pieces of a record while a parser walks a reply.</summary>
/// <remarks>
/// <see cref="WhoisRecord"/> is immutable, which is right for something handed to callers and wrong
/// for something being assembled field by field out of an unpredictable document. The builder holds
/// the mutable middle, and is public so that a custom parser can produce a record without
/// reimplementing any of this.
/// </remarks>
public sealed class WhoisRecordBuilder
{
    private readonly Dictionary<string, List<string>> _fields =
        new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

    private readonly List<string> _nameServers = new List<string>();
    private readonly HashSet<string> _nameServerKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _statuses = new List<string>();
    private readonly HashSet<string> _statusKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The domain name as the registry spells it.</summary>
    public string? DomainName { get; set; }

    /// <summary>The registry's identifier for the registration.</summary>
    public string? RegistryDomainId { get; set; }

    /// <summary>Sponsoring registrar.</summary>
    public string? Registrar { get; set; }

    /// <summary>The registrar's IANA identifier.</summary>
    public string? RegistrarIanaId { get; set; }

    /// <summary>The registrar's own WHOIS server.</summary>
    public string? RegistrarWhoisServer { get; set; }

    /// <summary>The registrar's web site.</summary>
    public string? RegistrarUrl { get; set; }

    /// <summary>Registrar abuse contact email.</summary>
    public string? RegistrarAbuseEmail { get; set; }

    /// <summary>Registrar abuse contact phone.</summary>
    public string? RegistrarAbusePhone { get; set; }

    /// <summary>Registration date.</summary>
    public DateTimeOffset? CreatedOn { get; set; }

    /// <summary>Last change date.</summary>
    public DateTimeOffset? UpdatedOn { get; set; }

    /// <summary>Expiry date.</summary>
    public DateTimeOffset? ExpiresOn { get; set; }

    /// <summary>Whether the zone is signed.</summary>
    public bool? DnsSecEnabled { get; set; }

    /// <summary>The party the domain is registered to.</summary>
    public DomainContactBuilder Registrant { get; } = new DomainContactBuilder(DomainContactType.Registrant);

    /// <summary>Administrative contact.</summary>
    public DomainContactBuilder Administrative { get; } = new DomainContactBuilder(DomainContactType.Administrative);

    /// <summary>Technical contact.</summary>
    public DomainContactBuilder Technical { get; } = new DomainContactBuilder(DomainContactType.Technical);

    /// <summary>Billing contact.</summary>
    public DomainContactBuilder Billing { get; } = new DomainContactBuilder(DomainContactType.Billing);

    /// <summary>Records a raw key/value pair exactly as the reply carried it.</summary>
    public void AddField(string key, string value)
    {
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmedKey = key.Trim();
        if (!_fields.TryGetValue(trimmedKey, out var values))
        {
            values = new List<string>(1);
            _fields[trimmedKey] = values;
        }

        values.Add(value.Trim());
    }

    /// <summary>Records a name server, ignoring duplicates and any glue address after it.</summary>
    public void AddNameServer(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        // "ns1.example.com 192.0.2.1" and "ns1.example.com [192.0.2.1]" both name one server.
        var host = value!.Trim().Split(new[] { ' ', '\t', '[', '(' }, StringSplitOptions.RemoveEmptyEntries)[0]
            .TrimEnd('.')
            .ToLowerInvariant();

        if (host.Length == 0 || host.IndexOf('.') < 0 || !_nameServerKeys.Add(host))
        {
            return;
        }

        _nameServers.Add(host);
    }

    /// <summary>Records a status code, ignoring duplicates.</summary>
    public void AddStatus(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var status = value!.Trim();

        // "clientTransferProhibited https://icann.org/epp#clientTransferProhibited" is one status
        // with its documentation link attached.
        var space = status.IndexOf(' ');
        if (space > 0 && status.IndexOf("https://", StringComparison.OrdinalIgnoreCase) > space)
        {
            status = status.Substring(0, space);
        }

        if (_statusKeys.Add(status))
        {
            _statuses.Add(status);
        }
    }

    /// <summary>Takes any value this builder is missing from <paramref name="other"/>.</summary>
    /// <remarks>
    /// Used to merge a registrar's fuller record into the registry's thin one without letting the
    /// registrar overwrite anything the registry is authoritative for.
    /// </remarks>
    public void FillMissingFrom(WhoisRecordBuilder other)
    {
        if (other is null)
        {
            return;
        }

        DomainName ??= other.DomainName;
        RegistryDomainId ??= other.RegistryDomainId;
        Registrar ??= other.Registrar;
        RegistrarIanaId ??= other.RegistrarIanaId;
        RegistrarWhoisServer ??= other.RegistrarWhoisServer;
        RegistrarUrl ??= other.RegistrarUrl;
        RegistrarAbuseEmail ??= other.RegistrarAbuseEmail;
        RegistrarAbusePhone ??= other.RegistrarAbusePhone;
        CreatedOn ??= other.CreatedOn;
        UpdatedOn ??= other.UpdatedOn;
        ExpiresOn ??= other.ExpiresOn;
        DnsSecEnabled ??= other.DnsSecEnabled;

        Registrant.FillMissingFrom(other.Registrant);
        Administrative.FillMissingFrom(other.Administrative);
        Technical.FillMissingFrom(other.Technical);
        Billing.FillMissingFrom(other.Billing);

        foreach (var nameServer in other._nameServers)
        {
            AddNameServer(nameServer);
        }

        foreach (var status in other._statuses)
        {
            AddStatus(status);
        }

        foreach (var field in other._fields)
        {
            if (!_fields.ContainsKey(field.Key))
            {
                _fields[field.Key] = new List<string>(field.Value);
            }
        }
    }

    /// <summary>Produces the immutable record.</summary>
    public WhoisRecord Build(string rawText)
    {
        var fields = new Dictionary<string, IReadOnlyList<string>>(_fields.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var field in _fields)
        {
            fields[field.Key] = field.Value.ToArray();
        }

        return new WhoisRecord
        {
            DomainName = DomainName,
            RegistryDomainId = RegistryDomainId,
            Registrar = Registrar,
            RegistrarIanaId = RegistrarIanaId,
            RegistrarWhoisServer = RegistrarWhoisServer,
            RegistrarUrl = RegistrarUrl,
            RegistrarAbuseEmail = RegistrarAbuseEmail,
            RegistrarAbusePhone = RegistrarAbusePhone,
            CreatedOn = CreatedOn,
            UpdatedOn = UpdatedOn,
            ExpiresOn = ExpiresOn,
            NameServers = _nameServers.ToArray(),
            Statuses = _statuses.ToArray(),
            DnsSecEnabled = DnsSecEnabled,
            Registrant = Registrant.BuildOrNull(),
            Administrative = Administrative.BuildOrNull(),
            Technical = Technical.BuildOrNull(),
            Billing = Billing.BuildOrNull(),
            Fields = fields,
            RawText = rawText ?? string.Empty,
        };
    }
}

/// <summary>Accumulates one contact while a parser walks a reply.</summary>
public sealed class DomainContactBuilder
{
    private readonly List<string> _street = new List<string>();

    /// <summary>Creates a builder for a contact in the given role.</summary>
    public DomainContactBuilder(DomainContactType type) => Type = type;

    /// <summary>Which role this contact plays.</summary>
    public DomainContactType Type { get; }

    /// <summary>Personal or role name.</summary>
    public string? Name { get; set; }

    /// <summary>Organisation.</summary>
    public string? Organization { get; set; }

    /// <summary>Email address.</summary>
    public string? Email { get; set; }

    /// <summary>Voice telephone number.</summary>
    public string? Phone { get; set; }

    /// <summary>Fax number.</summary>
    public string? Fax { get; set; }

    /// <summary>City.</summary>
    public string? City { get; set; }

    /// <summary>State, province or region.</summary>
    public string? StateOrProvince { get; set; }

    /// <summary>Postal code.</summary>
    public string? PostalCode { get; set; }

    /// <summary>Country.</summary>
    public string? Country { get; set; }

    /// <summary>Adds a line of street address.</summary>
    public void AddStreet(string? line)
    {
        if (!string.IsNullOrWhiteSpace(line))
        {
            _street.Add(line!.Trim());
        }
    }

    /// <summary>Takes any value this contact is missing from <paramref name="other"/>.</summary>
    public void FillMissingFrom(DomainContactBuilder other)
    {
        if (other is null)
        {
            return;
        }

        Name ??= other.Name;
        Organization ??= other.Organization;
        Email ??= other.Email;
        Phone ??= other.Phone;
        Fax ??= other.Fax;
        City ??= other.City;
        StateOrProvince ??= other.StateOrProvince;
        PostalCode ??= other.PostalCode;
        Country ??= other.Country;

        if (_street.Count == 0)
        {
            _street.AddRange(other._street);
        }
    }

    /// <summary>Produces the contact, or <see langword="null"/> when nothing was recorded.</summary>
    public DomainContact? BuildOrNull()
    {
        var contact = new DomainContact
        {
            Type = Type,
            Name = Name,
            Organization = Organization,
            Email = Email,
            Phone = Phone,
            Fax = Fax,
            Street = _street.ToArray(),
            City = City,
            StateOrProvince = StateOrProvince,
            PostalCode = PostalCode,
            Country = Country,
        };

        return contact.IsEmpty ? null : contact;
    }
}

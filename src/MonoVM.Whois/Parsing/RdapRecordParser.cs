using System;
using System.Collections.Generic;
using System.Text.Json;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Parsing;

/// <summary>
/// Parses an RDAP domain object (RFC 7483) into the same record type as a WHOIS text reply.
/// </summary>
/// <remarks>
/// RDAP is the protocol WHOIS should have been: a schema, real status codes, and contacts in
/// jCard rather than in prose. Mapping it onto the same <see cref="WhoisRecord"/> means callers do
/// not have to care which protocol their suffix happens to use.
/// </remarks>
public sealed class RdapRecordParser : IWhoisRecordParser
{
    /// <inheritdoc />
    public bool CanParse(WhoisResponse response)
    {
        if (response is null)
        {
            return false;
        }

        var text = response.Text.TrimStart();
        return text.Length > 0 && text[0] == '{';
    }

    /// <inheritdoc />
    public WhoisRecord Parse(WhoisResponse response)
    {
        if (response is null)
        {
            throw new ArgumentNullException(nameof(response));
        }

        var builder = new WhoisRecordBuilder();

        try
        {
            using var document = JsonDocument.Parse(response.Text);
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                return WhoisRecord.Empty;
            }

            // An error document (a 404 for a name that does not exist) has no record in it.
            if (root.TryGetProperty("errorCode", out _))
            {
                return WhoisRecord.Empty;
            }

            ReadDomain(root, builder);
            ReadStatuses(root, builder);
            ReadEvents(root, builder);
            ReadNameServers(root, builder);
            ReadSecureDns(root, builder);
            ReadEntities(root, builder, depth: 0);
        }
        catch (JsonException)
        {
            // A malformed document is not an exceptional condition here; the availability rules
            // have already had their say, and an empty record says "nothing could be read".
            return WhoisRecord.Empty;
        }

        return builder.Build(response.Text);
    }

    private static void ReadDomain(JsonElement root, WhoisRecordBuilder builder)
    {
        if (TryGetString(root, "ldhName", out var ldhName))
        {
            builder.DomainName = ldhName.ToLowerInvariant();
        }
        else if (TryGetString(root, "unicodeName", out var unicodeName))
        {
            builder.DomainName = unicodeName.ToLowerInvariant();
        }

        if (TryGetString(root, "handle", out var handle))
        {
            builder.RegistryDomainId = handle;
        }
    }

    private static void ReadStatuses(JsonElement root, WhoisRecordBuilder builder)
    {
        if (!root.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var entry in status.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.String)
            {
                builder.AddStatus(entry.GetString());
            }
        }
    }

    private static void ReadEvents(JsonElement root, WhoisRecordBuilder builder)
    {
        if (!root.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var entry in events.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object ||
                !TryGetString(entry, "eventAction", out var action) ||
                !TryGetString(entry, "eventDate", out var date))
            {
                continue;
            }

            var parsed = WhoisDateParser.Parse(date);
            if (parsed is null)
            {
                continue;
            }

            switch (action.ToLowerInvariant())
            {
                case "registration":
                    builder.CreatedOn ??= parsed;
                    break;
                case "last changed":
                case "last update of rdap database":
                case "last update":
                    builder.UpdatedOn ??= parsed;
                    break;
                case "expiration":
                    builder.ExpiresOn ??= parsed;
                    break;
            }
        }
    }

    private static void ReadNameServers(JsonElement root, WhoisRecordBuilder builder)
    {
        if (!root.TryGetProperty("nameservers", out var nameservers) || nameservers.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var entry in nameservers.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (TryGetString(entry, "ldhName", out var ldhName))
            {
                builder.AddNameServer(ldhName);
            }
            else if (TryGetString(entry, "unicodeName", out var unicodeName))
            {
                builder.AddNameServer(unicodeName);
            }
        }
    }

    private static void ReadSecureDns(JsonElement root, WhoisRecordBuilder builder)
    {
        if (!root.TryGetProperty("secureDNS", out var secureDns) || secureDns.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (secureDns.TryGetProperty("delegationSigned", out var signed) &&
            (signed.ValueKind == JsonValueKind.True || signed.ValueKind == JsonValueKind.False))
        {
            builder.DnsSecEnabled = signed.ValueKind == JsonValueKind.True;
        }
    }

    private static void ReadEntities(JsonElement parent, WhoisRecordBuilder builder, int depth)
    {
        // Registrars nest their abuse contact one level down; deeper than that is noise.
        if (depth > 2 || !parent.TryGetProperty("entities", out var entities) || entities.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var entity in entities.EnumerateArray())
        {
            if (entity.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var role in ReadRoles(entity))
            {
                switch (role)
                {
                    case "registrar":
                        ReadRegistrar(entity, builder);
                        break;
                    case "registrant":
                        ReadContact(entity, builder.Registrant);
                        break;
                    case "administrative":
                        ReadContact(entity, builder.Administrative);
                        break;
                    case "technical":
                        ReadContact(entity, builder.Technical);
                        break;
                    case "billing":
                        ReadContact(entity, builder.Billing);
                        break;
                    case "abuse":
                        ReadAbuse(entity, builder);
                        break;
                }
            }

            ReadEntities(entity, builder, depth + 1);
        }
    }

    private static IEnumerable<string> ReadRoles(JsonElement entity)
    {
        if (!entity.TryGetProperty("roles", out var roles) || roles.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var role in roles.EnumerateArray())
        {
            if (role.ValueKind == JsonValueKind.String)
            {
                yield return role.GetString()!.ToLowerInvariant();
            }
        }
    }

    private static void ReadRegistrar(JsonElement entity, WhoisRecordBuilder builder)
    {
        var card = VCard.Read(entity);
        builder.Registrar ??= card.Organization ?? card.Name;

        if (TryGetString(entity, "handle", out var handle))
        {
            builder.RegistrarIanaId ??= handle;
        }

        foreach (var link in ReadLinks(entity))
        {
            builder.RegistrarUrl ??= link;
            break;
        }
    }

    private static void ReadAbuse(JsonElement entity, WhoisRecordBuilder builder)
    {
        var card = VCard.Read(entity);
        builder.RegistrarAbuseEmail ??= card.Email;
        builder.RegistrarAbusePhone ??= card.Phone;
    }

    private static void ReadContact(JsonElement entity, DomainContactBuilder contact)
    {
        var card = VCard.Read(entity);

        contact.Name ??= card.Name;
        contact.Organization ??= card.Organization;
        contact.Email ??= card.Email;
        contact.Phone ??= card.Phone;
        contact.Fax ??= card.Fax;
        contact.City ??= card.City;
        contact.StateOrProvince ??= card.StateOrProvince;
        contact.PostalCode ??= card.PostalCode;
        contact.Country ??= card.Country;

        foreach (var street in card.Street)
        {
            contact.AddStreet(street);
        }
    }

    private static IEnumerable<string> ReadLinks(JsonElement entity)
    {
        if (!entity.TryGetProperty("links", out var links) || links.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var link in links.EnumerateArray())
        {
            if (link.ValueKind == JsonValueKind.Object && TryGetString(link, "href", out var href))
            {
                yield return href;
            }
        }
    }

    private static bool TryGetString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;

        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var text = property.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        value = text!.Trim();
        return true;
    }

    /// <summary>
    /// The jCard array RDAP carries contacts in.
    /// </summary>
    /// <remarks>
    /// The format is <c>["vcard", [[name, parameters, type, value], …]]</c> — an array of arrays,
    /// positional, with the value sometimes a string and sometimes an array of its own. Reading it
    /// defensively is the whole job.
    /// </remarks>
    private readonly struct VCard
    {
        private VCard(
            string? name, string? organization, string? email, string? phone, string? fax,
            IReadOnlyList<string> street, string? city, string? stateOrProvince, string? postalCode, string? country)
        {
            Name = name;
            Organization = organization;
            Email = email;
            Phone = phone;
            Fax = fax;
            Street = street;
            City = city;
            StateOrProvince = stateOrProvince;
            PostalCode = postalCode;
            Country = country;
        }

        public string? Name { get; }

        public string? Organization { get; }

        public string? Email { get; }

        public string? Phone { get; }

        public string? Fax { get; }

        public IReadOnlyList<string> Street { get; }

        public string? City { get; }

        public string? StateOrProvince { get; }

        public string? PostalCode { get; }

        public string? Country { get; }

        public static VCard Read(JsonElement entity)
        {
            string? name = null, organization = null, email = null, phone = null, fax = null;
            string? city = null, state = null, postalCode = null, country = null;
            var street = new List<string>();

            if (!entity.TryGetProperty("vcardArray", out var vcard) ||
                vcard.ValueKind != JsonValueKind.Array ||
                vcard.GetArrayLength() < 2)
            {
                return new VCard(null, null, null, null, null, Array.Empty<string>(), null, null, null, null);
            }

            var properties = vcard[1];
            if (properties.ValueKind != JsonValueKind.Array)
            {
                return new VCard(null, null, null, null, null, Array.Empty<string>(), null, null, null, null);
            }

            foreach (var property in properties.EnumerateArray())
            {
                if (property.ValueKind != JsonValueKind.Array || property.GetArrayLength() < 4)
                {
                    continue;
                }

                var field = property[0].ValueKind == JsonValueKind.String
                    ? property[0].GetString()?.ToLowerInvariant()
                    : null;

                if (field is null)
                {
                    continue;
                }

                var value = property[3];

                switch (field)
                {
                    case "fn":
                        name ??= AsText(value);
                        break;
                    case "org":
                        organization ??= AsText(value);
                        break;
                    case "email":
                        email ??= AsText(value);
                        break;
                    case "tel":
                        if (IsFax(property[1]))
                        {
                            fax ??= StripTelPrefix(AsText(value));
                        }
                        else
                        {
                            phone ??= StripTelPrefix(AsText(value));
                        }

                        break;
                    case "adr":
                        ReadAddress(value, street, ref city, ref state, ref postalCode, ref country);
                        break;
                }
            }

            return new VCard(name, organization, email, phone, fax, street, city, state, postalCode, country);
        }

        private static void ReadAddress(
            JsonElement value,
            ICollection<string> street,
            ref string? city,
            ref string? state,
            ref string? postalCode,
            ref string? country)
        {
            if (value.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            // jCard "adr": [po box, extended, street, locality, region, postal code, country].
            var parts = new List<string?>(7);
            foreach (var part in value.EnumerateArray())
            {
                parts.Add(AsText(part));
            }

            if (parts.Count > 2 && !string.IsNullOrWhiteSpace(parts[2]))
            {
                street.Add(parts[2]!);
            }

            if (parts.Count > 3)
            {
                city ??= Blank(parts[3]);
            }

            if (parts.Count > 4)
            {
                state ??= Blank(parts[4]);
            }

            if (parts.Count > 5)
            {
                postalCode ??= Blank(parts[5]);
            }

            if (parts.Count > 6)
            {
                country ??= Blank(parts[6]);
            }
        }

        private static bool IsFax(JsonElement parameters)
        {
            if (parameters.ValueKind != JsonValueKind.Object || !parameters.TryGetProperty("type", out var type))
            {
                return false;
            }

            if (type.ValueKind == JsonValueKind.String)
            {
                return string.Equals(type.GetString(), "fax", StringComparison.OrdinalIgnoreCase);
            }

            if (type.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var entry in type.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String &&
                    string.Equals(entry.GetString(), "fax", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static string? StripTelPrefix(string? value)
            => value is not null && value.StartsWith("tel:", StringComparison.OrdinalIgnoreCase)
                ? value.Substring(4)
                : value;

        private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value!.Trim();

        private static string? AsText(JsonElement value)
        {
            switch (value.ValueKind)
            {
                case JsonValueKind.String:
                    return Blank(value.GetString());

                case JsonValueKind.Array:
                    var joined = new List<string>();
                    foreach (var entry in value.EnumerateArray())
                    {
                        var text = AsText(entry);
                        if (text is not null)
                        {
                            joined.Add(text);
                        }
                    }

                    return joined.Count == 0 ? null : string.Join(" ", joined);

                case JsonValueKind.Number:
                    return value.GetRawText();

                default:
                    return null;
            }
        }
    }
}

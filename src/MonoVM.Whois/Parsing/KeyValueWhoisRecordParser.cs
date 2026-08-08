using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Parsing;

/// <summary>
/// Parses the line-oriented <c>key: value</c> text that port-43 servers return.
/// </summary>
/// <remarks>
/// <para>
/// There is no schema. What every registry does agree on is a key, a colon and a value, one to a
/// line, so that is what this reads — and then it maps the several hundred spellings registries use
/// for the same twenty facts onto the properties of <see cref="WhoisRecord"/>.
/// </para>
/// <para>
/// Anything unrecognised still reaches <see cref="WhoisRecord.Fields"/>, so no data is lost to this
/// parser's opinion of what matters. Redaction placeholders — "REDACTED FOR PRIVACY" and its many
/// cousins — are recorded there too, but are not promoted to typed properties: a caller checking
/// <c>Registrant.Email is null</c> should not get back the word "REDACTED".
/// </para>
/// </remarks>
public sealed class KeyValueWhoisRecordParser : IWhoisRecordParser
{
    private static readonly char[] KeyPadding = { ' ', '\t', '.', '_', '-', '·' };

    private static readonly Regex WhitespaceRun = new Regex(@"\s+", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] CommentPrefixes = { "%", "#", ";", ">>>", "--" };

    private static readonly HashSet<string> Placeholders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "redacted", "redacted for privacy", "redacted for gdpr", "data redacted", "data protected",
        "not disclosed", "not disclosed!", "non-public data", "gdpr masked", "statutory masking enabled",
        "n/a", "na", "none", "null", "-", "--", "not available", "unavailable", "withheld for privacy",
        "privacy protected", "please query the rdds service of the registrar of record",
    };

    private static readonly Dictionary<string, Action<WhoisRecordBuilder, string>> RecordFields =
        BuildRecordFields();

    private static readonly Dictionary<string, Action<DomainContactBuilder, string>> ContactFields =
        BuildContactFields();

    private static readonly (string Prefix, Func<WhoisRecordBuilder, DomainContactBuilder> Select)[] ContactPrefixes =
    {
        ("registrant", builder => builder.Registrant),
        ("holder", builder => builder.Registrant),
        ("owner", builder => builder.Registrant),
        ("administrative", builder => builder.Administrative),
        ("admin", builder => builder.Administrative),
        ("technical", builder => builder.Technical),
        ("tech", builder => builder.Technical),
        ("billing", builder => builder.Billing),
    };

    /// <inheritdoc />
    public bool CanParse(WhoisResponse response)
    {
        if (response is null)
        {
            return false;
        }

        if (response.Protocol == WhoisProtocol.Rdap)
        {
            return false;
        }

        var text = response.Text.TrimStart();
        return text.Length > 0 && text[0] != '{' && text[0] != '[';
    }

    /// <inheritdoc />
    public WhoisRecord Parse(WhoisResponse response)
    {
        if (response is null)
        {
            throw new ArgumentNullException(nameof(response));
        }

        var builder = new WhoisRecordBuilder();
        Populate(response.Text, builder);

        // A referral body is the registrar's fuller copy of the same registration. It fills gaps in
        // the registry's thin reply; it never overwrites what the registry said.
        foreach (var referral in response.Referrals)
        {
            var referralBuilder = new WhoisRecordBuilder();
            Populate(referral.Text, referralBuilder);
            builder.FillMissingFrom(referralBuilder);
        }

        return builder.Build(response.Text);
    }

    /// <summary>Reads every <c>key: value</c> line of <paramref name="text"/> into <paramref name="builder"/>.</summary>
    public static void Populate(string text, WhoisRecordBuilder builder)
    {
        if (string.IsNullOrEmpty(text) || builder is null)
        {
            return;
        }

        foreach (var rawLine in text.SplitLines())
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || IsComment(line))
            {
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0 || colon == line.Length - 1)
            {
                continue;
            }

            var key = line.Substring(0, colon).TrimEnd(KeyPadding).Trim();
            var value = line.Substring(colon + 1).Trim();

            if (key.Length == 0 || value.Length == 0)
            {
                continue;
            }

            builder.AddField(key, value);

            if (IsPlaceholder(value))
            {
                continue;
            }

            Apply(builder, Normalize(key), value);
        }
    }

    private static void Apply(WhoisRecordBuilder builder, string key, string value)
    {
        if (RecordFields.TryGetValue(key, out var setter))
        {
            setter(builder, value);
            return;
        }

        foreach (var (prefix, select) in ContactPrefixes)
        {
            if (!key.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            var remainder = key.Substring(prefix.Length).Trim();
            if (remainder.Length == 0)
            {
                // A bare "Registrant: Acme Ltd" names the party.
                var contact = select(builder);
                contact.Name ??= value;
                return;
            }

            // "Registrant Contact Email" and "Registrant Email" mean the same thing.
            if (remainder.StartsWith("contact", StringComparison.Ordinal))
            {
                remainder = remainder.Substring("contact".Length).Trim();
            }

            if (remainder.Length > 0 && ContactFields.TryGetValue(remainder, out var contactSetter))
            {
                contactSetter(select(builder), value);
                return;
            }
        }
    }

    /// <summary>Reduces a key to a canonical form: lower case, no padding, single spaces.</summary>
    internal static string Normalize(string key)
    {
        var text = key.Trim().Trim(KeyPadding).ToLowerInvariant().Replace('_', ' ').Replace('/', ' ');
        return WhitespaceRun.Replace(text, " ").Trim();
    }

    private static bool IsComment(string line)
    {
        foreach (var prefix in CommentPrefixes)
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsPlaceholder(string value)
    {
        if (Placeholders.Contains(value))
        {
            return true;
        }

        if (value.IndexOf("redacted", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return true;
        }

        // "Privacy protected" is a placeholder; "contact@withheldforprivacy.com" is a working
        // address the registrar wants used, so an "@" means the value is real.
        return value.IndexOf("privacy", StringComparison.OrdinalIgnoreCase) >= 0
               && value.IndexOf('@') < 0;
    }

    private static Dictionary<string, Action<WhoisRecordBuilder, string>> BuildRecordFields()
    {
        var map = new Dictionary<string, Action<WhoisRecordBuilder, string>>(StringComparer.Ordinal);

        void Add(Action<WhoisRecordBuilder, string> setter, params string[] keys)
        {
            foreach (var key in keys)
            {
                map[key] = setter;
            }
        }

        Add((b, v) => b.DomainName ??= v.TrimEnd('.').ToLowerInvariant(),
            "domain name", "domain", "domainname", "domain-name", "the queried object", "ascii");

        Add((b, v) => b.RegistryDomainId ??= v,
            "registry domain id", "domain id", "roid", "nic-hdl");

        Add((b, v) => b.Registrar ??= v,
            "registrar", "sponsoring registrar", "registrar name", "registrar organization",
            "registrar organisation", "registration service provider", "registrar handle");

        Add((b, v) => b.RegistrarIanaId ??= v,
            "registrar iana id", "iana id", "sponsoring registrar iana id");

        Add((b, v) => b.RegistrarWhoisServer ??= v.ToLowerInvariant(),
            "registrar whois server", "whois server", "whois");

        Add((b, v) => b.RegistrarUrl ??= v,
            "registrar url", "registrar website", "referral url", "url");

        Add((b, v) => b.RegistrarAbuseEmail ??= v,
            "registrar abuse contact email", "abuse contact email", "abuse email");

        Add((b, v) => b.RegistrarAbusePhone ??= v,
            "registrar abuse contact phone", "abuse contact phone", "abuse phone");

        Add((b, v) => b.CreatedOn ??= WhoisDateParser.Parse(v),
            "creation date", "created", "created on", "created date", "create date", "registered",
            "registered on", "registration date", "registration time", "domain registration date",
            "domain record activated", "activated", "registered date", "record created");

        Add((b, v) => b.UpdatedOn ??= WhoisDateParser.Parse(v),
            "updated date", "updated", "updated on", "last updated", "last update", "last modified",
            "changed", "modified", "domain record last updated", "record last updated", "last-update");

        Add((b, v) => b.ExpiresOn ??= WhoisDateParser.Parse(v),
            "expiry date", "expiration date", "expires", "expires on", "expire date", "expiry",
            "registry expiry date", "registrar registration expiration date", "paid-till", "paid till",
            "renewal date", "valid until", "expiration time", "domain expiration date", "record expires on");

        Add((b, v) => b.AddNameServer(v),
            "name server", "nameserver", "nserver", "name servers", "nameservers", "ns", "dns",
            "domain nameservers", "host name");

        Add((b, v) => b.AddStatus(v),
            "domain status", "status", "state", "epp status", "eppstatus", "domain state");

        Add((b, v) => b.DnsSecEnabled ??= ReadDnsSec(v),
            "dnssec", "dnssec status", "signed");

        return map;
    }

    private static Dictionary<string, Action<DomainContactBuilder, string>> BuildContactFields()
    {
        var map = new Dictionary<string, Action<DomainContactBuilder, string>>(StringComparer.Ordinal);

        void Add(Action<DomainContactBuilder, string> setter, params string[] keys)
        {
            foreach (var key in keys)
            {
                map[key] = setter;
            }
        }

        Add((c, v) => c.Name ??= v, "name", "person", "contact");
        Add((c, v) => c.Organization ??= v, "organization", "organisation", "org", "company", "organization name");
        Add((c, v) => c.Email ??= v, "email", "e-mail", "email address", "e-mail address", "mail");
        Add((c, v) => c.Phone ??= v, "phone", "phone number", "telephone", "voice", "tel");
        Add((c, v) => c.Fax ??= v, "fax", "fax number", "facsimile", "fax-no");
        Add((c, v) => c.AddStreet(v), "street", "address", "street address", "address line", "postal address");
        Add((c, v) => c.City ??= v, "city", "town");
        Add((c, v) => c.StateOrProvince ??= v, "state province", "state", "province", "region");
        Add((c, v) => c.PostalCode ??= v, "postal code", "postalcode", "zip", "zip code", "post code");
        Add((c, v) => c.Country ??= v, "country", "country code", "country name");

        return map;
    }

    private static bool? ReadDnsSec(string value)
    {
        var text = value.Trim().ToLowerInvariant();

        if (text.Length == 0)
        {
            return null;
        }

        if (text.StartsWith("unsigned", StringComparison.Ordinal) || text == "no" || text == "false" ||
            text.IndexOf("no dnssec", StringComparison.Ordinal) >= 0)
        {
            return false;
        }

        if (text.StartsWith("signed", StringComparison.Ordinal) || text == "yes" || text == "true" ||
            text.IndexOf("signeddelegation", StringComparison.Ordinal) >= 0 ||
            text.IndexOf("signed delegation", StringComparison.Ordinal) >= 0)
        {
            return true;
        }

        return null;
    }
}

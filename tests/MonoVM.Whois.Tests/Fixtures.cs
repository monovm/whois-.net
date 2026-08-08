namespace MonoVM.Whois.Tests;

/// <summary>
/// Replies captured from real registries, trimmed but not reworded.
/// </summary>
/// <remarks>
/// Detection is only as good as the text it was calibrated against, so the fixtures keep the parts
/// that actually cause trouble: the legal boilerplate, the padded keys, the status codes with URLs
/// attached.
/// </remarks>
internal static class Fixtures
{
    /// <summary>A thin registry reply for a registered .com, complete with its footer.</summary>
    public const string ComRecord = """
   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrar.test
   Registrar URL: http://www.registrar.test
   Updated Date: 2025-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Registrar: Example Registrar, LLC
   Registrar IANA ID: 376
   Registrar Abuse Contact Email: abuse@registrar.test
   Registrar Abuse Contact Phone: +1.5555550100
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2026-01-01T00:00:00Z <<<

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire.
""";

    /// <summary>The registrar's fuller copy of the same registration, reached through the referral.</summary>
    public const string RegistrarRecord = """
Domain Name: example.com
Registrar: Example Registrar, LLC
Registrant Organization: Example Holdings Ltd
Registrant Country: GB
Registrant Email: REDACTED FOR PRIVACY
Admin Organization: Example Holdings Ltd
Tech Email: hostmaster@example.com
Name Server: c.iana-servers.net
""";

    /// <summary>An RDAP domain object for a registered name.</summary>
    public const string RdapRecord = """
{
  "rdapConformance": ["rdap_level_0", "icann_rdap_response_profile_0"],
  "objectClassName": "domain",
  "handle": "D123456-SHOP",
  "ldhName": "example.shop",
  "status": ["client transfer prohibited", "active"],
  "events": [
    { "eventAction": "registration", "eventDate": "2019-06-25T09:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2027-06-25T09:00:00Z" },
    { "eventAction": "last changed", "eventDate": "2025-05-01T12:30:00Z" }
  ],
  "nameservers": [
    { "objectClassName": "nameserver", "ldhName": "ns1.example-dns.test" },
    { "objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE-DNS.TEST" }
  ],
  "secureDNS": { "delegationSigned": true },
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "1234",
      "roles": ["registrar"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Example Registrar KK"]
      ]],
      "entities": [
        {
          "objectClassName": "entity",
          "roles": ["abuse"],
          "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Abuse Desk"],
            ["email", {}, "text", "abuse@registrar.example"],
            ["tel", {"type": ["voice"]}, "uri", "tel:+81.312345678"]
          ]]
        }
      ]
    },
    {
      "objectClassName": "entity",
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Taro Yamada"],
        ["org", {}, "text", "Example KK"],
        ["adr", {}, "text", ["", "", "1-2-3 Shibuya", "Tokyo", "", "150-0002", "JP"]],
        ["email", {}, "text", "owner@example.shop"],
        ["tel", {"type": ["fax"]}, "uri", "tel:+81.312345679"]
      ]]
    }
  ]
}
""";

    /// <summary>A .fi style reply whose keys are padded out with dots.</summary>
    public const string DottedKeyRecord = """
domain.............: example.fi
status.............: Registered
created............: 12.3.2004
expires............: 12.3.2027
name...............: Example Oy
nserver............: ns1.example.fi
""";
}

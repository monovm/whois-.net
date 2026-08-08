using System;
using System.Linq;
using MonoVM.Whois.Model;
using MonoVM.Whois.Parsing;
using Xunit;

namespace MonoVM.Whois.Tests;

public class KeyValueRecordParserTests
{
    private static readonly KeyValueWhoisRecordParser Parser = new KeyValueWhoisRecordParser();

    private static WhoisResponse Response(string text, params WhoisResponse[] referrals)
        => new WhoisResponse(
            DomainName.Parse("example.com"), text, WhoisProtocol.Whois43, "whois.test",
            TimeSpan.Zero, referrals: referrals);

    [Fact]
    public void Reads_the_fields_of_a_thin_registry_record()
    {
        var record = Parser.Parse(Response(Fixtures.ComRecord));

        Assert.Equal("example.com", record.DomainName);
        Assert.Equal("2336799_DOMAIN_COM-VRSN", record.RegistryDomainId);
        Assert.Equal("Example Registrar, LLC", record.Registrar);
        Assert.Equal("376", record.RegistrarIanaId);
        Assert.Equal("whois.registrar.test", record.RegistrarWhoisServer);
        Assert.Equal("abuse@registrar.test", record.RegistrarAbuseEmail);
        Assert.True(record.DnsSecEnabled);
    }

    [Fact]
    public void Reads_iso_dates()
    {
        var record = Parser.Parse(Response(Fixtures.ComRecord));

        Assert.Equal(new DateTimeOffset(1995, 8, 14, 4, 0, 0, TimeSpan.Zero), record.CreatedOn);
        Assert.Equal(new DateTimeOffset(2026, 8, 13, 4, 0, 0, TimeSpan.Zero), record.ExpiresOn);
        Assert.Equal(new DateTimeOffset(2025, 8, 14, 7, 1, 34, TimeSpan.Zero), record.UpdatedOn);
    }

    [Fact]
    public void Collects_name_servers_lower_cased_and_deduplicated()
    {
        var record = Parser.Parse(Response(Fixtures.ComRecord));

        Assert.Equal(new[] { "a.iana-servers.net", "b.iana-servers.net" }, record.NameServers);
    }

    [Fact]
    public void Keeps_the_status_code_and_drops_the_documentation_link()
    {
        var record = Parser.Parse(Response(Fixtures.ComRecord));

        Assert.Contains("clientDeleteProhibited", record.Statuses);
        Assert.DoesNotContain(record.Statuses, status => status.Contains("https://"));
        Assert.True(record.HasStatus("transferprohibited"));
    }

    [Fact]
    public void Reads_keys_padded_out_with_dots()
    {
        var record = Parser.Parse(Response(Fixtures.DottedKeyRecord));

        Assert.Equal("example.fi", record.DomainName);
        Assert.Contains("Registered", record.Statuses);
        Assert.Equal(new[] { "ns1.example.fi" }, record.NameServers);
        Assert.Equal(2004, record.CreatedOn?.Year);
    }

    [Fact]
    public void Keeps_every_key_it_did_not_recognise()
    {
        var record = Parser.Parse(Response("Weird Registry Key: some value\nDomain Name: example.com"));

        Assert.Equal("some value", record.Field("Weird Registry Key"));
        Assert.Equal("example.com", record.DomainName);
    }

    [Fact]
    public void Does_not_promote_a_redaction_placeholder_to_a_typed_field()
    {
        var record = Parser.Parse(Response("Registrant Email: REDACTED FOR PRIVACY\nRegistrant Country: GB"));

        Assert.Null(record.Registrant?.Email);
        Assert.Equal("GB", record.Registrant?.Country);

        // The placeholder is still there for anyone who wants to know it was redacted.
        Assert.Equal("REDACTED FOR PRIVACY", record.Field("Registrant Email"));
    }

    [Fact]
    public void Reads_contacts_by_role()
    {
        const string Text = """
Registrant Name: Alice Example
Registrant Organization: Example Ltd
Registrant Street: 1 Example Way
Registrant City: London
Registrant Postal Code: EC1A 1BB
Registrant Country: GB
Admin Email: admin@example.com
Tech Phone: +44.2071234567
Billing Organization: Example Billing Ltd
""";

        var record = Parser.Parse(Response(Text));

        Assert.Equal("Alice Example", record.Registrant?.Name);
        Assert.Equal("Example Ltd", record.Registrant?.Organization);
        Assert.Equal("London", record.Registrant?.City);
        Assert.Equal(new[] { "1 Example Way" }, record.Registrant?.Street);
        Assert.Equal("admin@example.com", record.Administrative?.Email);
        Assert.Equal("+44.2071234567", record.Technical?.Phone);
        Assert.Equal("Example Billing Ltd", record.Billing?.Organization);
    }

    [Fact]
    public void Fills_gaps_from_a_referral_without_overwriting_the_registry()
    {
        var referral = new WhoisResponse(
            DomainName.Parse("example.com"), Fixtures.RegistrarRecord, WhoisProtocol.Whois43,
            "whois.registrar.test", TimeSpan.Zero);

        var record = Parser.Parse(Response(Fixtures.ComRecord, referral));

        // The registry stays authoritative for what it published.
        Assert.Equal("Example Registrar, LLC", record.Registrar);
        Assert.Equal(new DateTimeOffset(1995, 8, 14, 4, 0, 0, TimeSpan.Zero), record.CreatedOn);

        // The registrar supplies what the registry withheld.
        Assert.Equal("Example Holdings Ltd", record.Registrant?.Organization);
        Assert.Equal("GB", record.Registrant?.Country);
        Assert.Contains("c.iana-servers.net", record.NameServers);
    }

    [Fact]
    public void Ignores_comment_lines()
    {
        var record = Parser.Parse(Response("% Domain Name: not-a-record.com\nDomain Name: example.com"));

        Assert.Equal("example.com", record.DomainName);
    }

    [Fact]
    public void Declines_json()
    {
        Assert.False(Parser.CanParse(new WhoisResponse(
            DomainName.Parse("example.shop"), Fixtures.RdapRecord, WhoisProtocol.Rdap, "rdap.test", TimeSpan.Zero)));
    }
}

public class RdapRecordParserTests
{
    private static readonly RdapRecordParser Parser = new RdapRecordParser();

    private static WhoisResponse Response(string text, int status = 200)
        => new WhoisResponse(
            DomainName.Parse("example.shop"), text, WhoisProtocol.Rdap, "rdap.test", TimeSpan.Zero, status);

    [Fact]
    public void Reads_the_domain_and_its_events()
    {
        var record = Parser.Parse(Response(Fixtures.RdapRecord));

        Assert.Equal("example.shop", record.DomainName);
        Assert.Equal("D123456-SHOP", record.RegistryDomainId);
        Assert.Equal(2019, record.CreatedOn?.Year);
        Assert.Equal(2027, record.ExpiresOn?.Year);
        Assert.Equal(2025, record.UpdatedOn?.Year);
        Assert.True(record.DnsSecEnabled);
    }

    [Fact]
    public void Reads_name_servers_and_statuses()
    {
        var record = Parser.Parse(Response(Fixtures.RdapRecord));

        Assert.Equal(new[] { "ns1.example-dns.test", "ns2.example-dns.test" }, record.NameServers);
        Assert.Contains("active", record.Statuses);
    }

    [Fact]
    public void Reads_entities_by_role_including_the_nested_abuse_contact()
    {
        var record = Parser.Parse(Response(Fixtures.RdapRecord));

        Assert.Equal("Example Registrar KK", record.Registrar);
        Assert.Equal("abuse@registrar.example", record.RegistrarAbuseEmail);
        Assert.Equal("+81.312345678", record.RegistrarAbusePhone);
    }

    [Fact]
    public void Reads_a_jcard_contact_including_its_address()
    {
        var record = Parser.Parse(Response(Fixtures.RdapRecord));
        var registrant = record.Registrant;

        Assert.NotNull(registrant);
        Assert.Equal("Taro Yamada", registrant!.Name);
        Assert.Equal("Example KK", registrant.Organization);
        Assert.Equal("owner@example.shop", registrant.Email);
        Assert.Equal("Tokyo", registrant.City);
        Assert.Equal("150-0002", registrant.PostalCode);
        Assert.Equal("JP", registrant.Country);
        Assert.Equal(new[] { "1-2-3 Shibuya" }, registrant.Street);

        // The number was tagged "fax", so it is not reported as a phone number.
        Assert.Equal("+81.312345679", registrant.Fax);
        Assert.Null(registrant.Phone);
    }

    [Fact]
    public void Returns_an_empty_record_for_an_error_document()
    {
        var record = Parser.Parse(Response("""{"errorCode": 404, "title": "Not Found"}""", 404));

        Assert.True(record.IsEmpty);
    }

    [Fact]
    public void Returns_an_empty_record_for_malformed_json()
    {
        Assert.True(Parser.Parse(Response("{ not json")).IsEmpty);
    }
}

public class WhoisDateParserTests
{
    [Theory]
    [InlineData("2020-01-02T03:04:05Z", 2020, 1, 2)]
    [InlineData("2020-01-02 03:04:05", 2020, 1, 2)]
    [InlineData("02-Jan-2020", 2020, 1, 2)]
    [InlineData("2020.01.02", 2020, 1, 2)]
    [InlineData("2020/01/02", 2020, 1, 2)]
    [InlineData("20200102", 2020, 1, 2)]
    [InlineData("02.01.2020", 2020, 1, 2)]
    [InlineData("2020-01-02T03:04:05Z (registry local time)", 2020, 1, 2)]
    public void Reads_the_formats_registries_actually_use(string value, int year, int month, int day)
    {
        var parsed = WhoisDateParser.Parse(value);

        Assert.NotNull(parsed);
        Assert.Equal(year, parsed!.Value.Year);
        Assert.Equal(month, parsed.Value.Month);
        Assert.Equal(day, parsed.Value.Day);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a date")]
    [InlineData("0000-00-00")]
    [InlineData("1601-01-01")]
    public void Leaves_a_value_it_cannot_read_unparsed(string value)
    {
        Assert.Null(WhoisDateParser.Parse(value));
    }
}

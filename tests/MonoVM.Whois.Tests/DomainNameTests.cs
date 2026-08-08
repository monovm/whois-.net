using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;
using MonoVM.Whois.Registry;
using Xunit;

namespace MonoVM.Whois.Tests;

public class DomainNameTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("  Example.COM  ", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("https://example.com/pricing?x=1", "example.com")]
    [InlineData("HTTPS://WWW.Example.COM:8080/path", "www.example.com")]
    [InlineData("user:pass@example.com", "example.com")]
    [InlineData("example.com#anchor", "example.com")]
    public void Normalizes_whatever_a_user_pastes(string input, string expected)
    {
        Assert.True(DomainName.TryParse(input, out var domain));
        Assert.Equal(expected, domain.Unicode);
    }

    [Fact]
    public void Converts_internationalised_names_both_ways()
    {
        var domain = DomainName.FromParts("münchen", ".de");

        Assert.Equal("münchen.de", domain.Unicode);
        Assert.Equal("xn--mnchen-3ya.de", domain.Ascii);
        Assert.True(domain.IsInternationalized);
        Assert.True(domain.IsWellFormed);
    }

    [Fact]
    public void Treats_the_punycode_and_unicode_forms_as_the_same_name()
    {
        var unicode = DomainName.Parse("münchen.de");
        var ascii = DomainName.Parse("xn--mnchen-3ya.de");

        Assert.Equal(unicode, ascii);
        Assert.Equal(unicode.GetHashCode(), ascii.GetHashCode());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".")]
    [InlineData("https://")]
    public void Rejects_input_with_no_host(string input)
    {
        Assert.False(DomainName.TryParse(input, out _));
    }

    [Fact]
    public void Accepts_a_suffix_with_or_without_its_dot()
    {
        Assert.Equal(".net", DomainName.FromParts("example", "net").Tld);
        Assert.Equal(".net", DomainName.FromParts("example", ".net").Tld);
        Assert.Equal(".net", DomainName.FromParts("example", ".NET.").Tld);
    }

    [Fact]
    public void Reports_a_bare_label_as_having_no_suffix()
    {
        var domain = DomainName.Parse("monovm");

        Assert.False(domain.HasTld);
        Assert.Equal("monovm", domain.Sld);
        Assert.Equal(string.Empty, domain.Tld);
    }
}

public class DomainNameParserTests
{
    private static readonly DomainNameParser Parser = new DomainNameParser(TestServers.Registry());

    [Fact]
    public void Prefers_the_longest_known_suffix()
    {
        var domain = Parser.Parse("example.co.uk");

        Assert.Equal("example", domain.Sld);
        Assert.Equal(".co.uk", domain.Tld);
    }

    [Fact]
    public void Strips_subdomains()
    {
        var domain = Parser.Parse("https://shop.eu.example.co.uk/cart");

        Assert.Equal("example", domain.Sld);
        Assert.Equal(".co.uk", domain.Tld);
        Assert.Equal("example.co.uk", domain.Unicode);
    }

    [Fact]
    public void Falls_back_to_the_first_dot_for_an_unknown_suffix()
    {
        var domain = Parser.Parse("example.invalidtld");

        Assert.Equal("example", domain.Sld);
        Assert.Equal(".invalidtld", domain.Tld);
    }

    [Fact]
    public void Rejects_a_bare_suffix()
    {
        Assert.False(Parser.TryParse("co.uk", out _, out var error));
        Assert.Contains("bare suffix", error);
    }

    [Fact]
    public void Rejects_a_malformed_label()
    {
        Assert.False(Parser.TryParse("-nope-.com", out _, out _));
    }

    [Fact]
    public void Throws_with_the_reason_when_asked_to_parse()
    {
        var exception = Assert.Throws<InvalidDomainException>(() => Parser.Parse("   "));
        Assert.Equal(WhoisErrorCode.InvalidDomain, exception.Code);
    }
}

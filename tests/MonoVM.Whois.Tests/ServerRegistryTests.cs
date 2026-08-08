using System.Linq;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;
using MonoVM.Whois.Registry;
using Xunit;

namespace MonoVM.Whois.Tests;

public class ServerDefinitionTests
{
    [Fact]
    public void Reads_a_socket_endpoint_with_the_default_port()
    {
        var definition = WhoisServerDefinition.Create(".com", "socket://whois.verisign-grs.com");

        Assert.Equal(WhoisProtocol.Whois43, definition.Protocol);
        Assert.Equal("whois.verisign-grs.com", definition.Host);
        Assert.Equal(43, definition.Port);
    }

    [Fact]
    public void Reads_a_socket_endpoint_with_an_explicit_port()
    {
        var definition = WhoisServerDefinition.Create(".li", "socket://whois.nic.ch:4343");

        Assert.Equal("whois.nic.ch", definition.Host);
        Assert.Equal(4343, definition.Port);
    }

    [Fact]
    public void Reads_an_rdap_endpoint()
    {
        var definition = WhoisServerDefinition.Create(".shop", "https://rdap.gmoregistry.net/rdap/domain/");

        Assert.Equal(WhoisProtocol.Rdap, definition.Protocol);
        Assert.Equal("rdap.gmoregistry.net", definition.Host);
    }

    [Fact]
    public void Normalises_the_suffix()
    {
        Assert.Equal(".com", WhoisServerDefinition.Create("COM", "socket://x.test").Tld);
        Assert.Equal(".com", WhoisServerDefinition.Create(".com.", "socket://x.test").Tld);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ftp://whois.test")]
    [InlineData("socket://")]
    public void Rejects_an_unusable_endpoint(string uri)
    {
        Assert.Throws<WhoisDefinitionException>(() => WhoisServerDefinition.Create(".com", uri));
    }
}

public class WhoisServerRegistryTests
{
    [Fact]
    public void Finds_the_longest_matching_suffix()
    {
        var registry = TestServers.Registry();

        Assert.Equal(".co.uk", registry.FindLongestSuffix("example.co.uk"));
        Assert.Equal(".com", registry.FindLongestSuffix("example.com"));
        Assert.Equal(".co.uk", registry.FindLongestSuffix("a.b.example.co.uk"));
        Assert.Null(registry.FindLongestSuffix("example.unknown"));
    }

    [Fact]
    public void Matches_suffixes_case_insensitively()
    {
        var registry = TestServers.Registry();

        Assert.True(registry.Supports(".COM"));
        Assert.True(registry.Supports("com"));
        Assert.True(registry.TryGet(".Com", out var definition));
        Assert.Equal(".com", definition!.Tld);
    }

    [Fact]
    public void Rejects_an_empty_table()
    {
        Assert.Throws<WhoisDefinitionException>(
            () => new WhoisServerRegistry(System.Array.Empty<WhoisServerDefinition>(), "empty"));
    }

    [Fact]
    public void The_bundled_table_covers_the_common_suffixes()
    {
        var registry = WhoisServerRegistry.CreateDefault();

        Assert.True(registry.Count > 250, $"expected a few hundred suffixes, found {registry.Count}");

        foreach (var tld in new[] { ".com", ".net", ".org", ".info", ".io", ".dev", ".co.uk", ".de", ".ir" })
        {
            Assert.True(registry.Supports(tld), $"the bundled table should serve {tld}");
        }
    }

    [Fact]
    public void Every_bundled_entry_has_a_usable_endpoint()
    {
        var registry = WhoisServerRegistry.CreateDefault();

        foreach (var definition in registry.Definitions)
        {
            Assert.False(string.IsNullOrWhiteSpace(definition.Host), $"{definition.Tld} names no host");
            Assert.InRange(definition.Port, 1, 65535);
            Assert.StartsWith(".", definition.Tld);
            Assert.Equal(definition.Tld.ToLowerInvariant(), definition.Tld);
        }
    }
}

public class DefinitionSourceTests
{
    private const string OverrideJson = """
    [
      { "extensions": ".com", "uri": "socket://whois.example.test", "available": "NOPE" },
      { "extensions": ".test,.example", "uri": "socket://whois.other.test", "available_when_empty": true }
    ]
    """;

    [Fact]
    public void A_later_source_overrides_an_earlier_one_suffix_by_suffix()
    {
        var composite = new CompositeWhoisServerDefinitionSource(
            EmbeddedWhoisServerDefinitionSource.Instance,
            new JsonStringWhoisServerDefinitionSource(OverrideJson, "override"));

        var registry = new WhoisServerRegistry(composite);

        Assert.True(registry.TryGet(".com", out var com));
        Assert.Equal("whois.example.test", com!.Host);
        Assert.Equal("override", com.Source);

        // Everything not named in the override is left exactly as it was.
        Assert.True(registry.TryGet(".org", out var org));
        Assert.Equal("bundled", org!.Source);
    }

    [Fact]
    public void Expands_a_comma_separated_extension_list()
    {
        var definitions = WhoisServerDefinitionJsonReader.Read(OverrideJson, "test").ToList();

        Assert.Equal(3, definitions.Count);
        Assert.Contains(definitions, d => d.Tld == ".test");
        Assert.Contains(definitions, d => d.Tld == ".example");
    }

    [Fact]
    public void Reads_a_flag_written_as_a_json_boolean()
    {
        var definitions = WhoisServerDefinitionJsonReader.Read(OverrideJson, "test").ToList();

        Assert.True(definitions.Single(d => d.Tld == ".test").AvailableWhenEmpty);
        Assert.False(definitions.Single(d => d.Tld == ".com").AvailableWhenEmpty);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("[{\"uri\": \"socket://x.test\"}]")]
    [InlineData("[{\"extensions\": \".x\"}]")]
    public void Rejects_a_malformed_table(string json)
    {
        Assert.Throws<WhoisDefinitionException>(
            () => WhoisServerDefinitionJsonReader.Read(json, "test"));
    }

    [Fact]
    public void A_missing_optional_file_is_not_an_error()
    {
        var source = new JsonFileWhoisServerDefinitionSource("does-not-exist.json");
        Assert.Empty(source.Load());
    }

    [Fact]
    public void A_missing_required_file_is_an_error()
    {
        var source = new JsonFileWhoisServerDefinitionSource("does-not-exist.json", required: true);
        Assert.Throws<WhoisDefinitionException>(() => source.Load().ToList());
    }
}

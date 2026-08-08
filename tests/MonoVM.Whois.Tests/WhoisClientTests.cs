using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.DependencyInjection;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;
using Xunit;

namespace MonoVM.Whois.Tests;

public class WhoisClientTests
{
    private static WhoisClient Build(FakeTransport transport, Action<WhoisClientBuilder>? configure = null)
    {
        var builder = WhoisClient.CreateBuilder()
            .WithRegistry(TestServers.Registry())
            .WithTransportFactory(transport)
            .WithPopularTlds(".com", ".co.uk");

        configure?.Invoke(builder);
        return builder.Build();
    }

    [Fact]
    public async Task Reports_an_unregistered_name_as_available()
    {
        var transport = new FakeTransport().Reply("free123.com", "No match for \"FREE123.COM\".");
        using var client = Build(transport);

        var result = await client.LookupAsync("free123.com");

        Assert.Equal(DomainAvailabilityStatus.Available, result.Status);
        Assert.True(result.IsAvailable);
        Assert.Equal("free123.com is available for registration.", result.Message);
    }

    [Fact]
    public async Task Reports_a_registered_name_and_parses_its_record()
    {
        var transport = new FakeTransport().Reply("example.com", Fixtures.ComRecord);
        using var client = Build(transport);

        var result = await client.LookupAsync("https://WWW.Example.COM/pricing");

        Assert.Equal(DomainAvailabilityStatus.Registered, result.Status);
        Assert.Equal("example.com", result.Domain?.Unicode);
        Assert.Equal("Example Registrar, LLC", result.Record?.Registrar);
        Assert.Equal(2, result.Record?.NameServers.Count);
    }

    [Fact]
    public async Task Reports_an_unknown_suffix_as_invalid_without_asking_anyone()
    {
        var transport = new FakeTransport();
        using var client = Build(transport);

        var result = await client.LookupAsync("example.nosuchtld");

        Assert.Equal(DomainAvailabilityStatus.Invalid, result.Status);
        Assert.Equal(0, transport.CallCount);
        Assert.Contains("No WHOIS or RDAP server is known", result.Message);
    }

    [Fact]
    public async Task Reports_a_refusal_as_an_error_never_as_available()
    {
        var transport = new FakeTransport()
            .Throw("example.com", new WhoisServerException("Request limit exceeded.", "whois.test"));

        using var client = Build(transport);
        var result = await client.LookupAsync("example.com");

        Assert.Equal(DomainAvailabilityStatus.Error, result.Status);
        Assert.False(result.IsAvailable);
        Assert.Equal(WhoisErrorCode.ServerRefused, result.ErrorCode);
    }

    [Fact]
    public async Task Throws_instead_when_asked_to()
    {
        var transport = new FakeTransport()
            .Throw("example.com", new WhoisConnectionException("unreachable", "whois.test"));

        using var client = Build(transport, builder => builder.ThrowOnFailure());

        await Assert.ThrowsAsync<WhoisConnectionException>(() => client.LookupAsync("example.com"));
    }

    [Fact]
    public async Task Expands_a_bare_label_across_the_popular_suffixes()
    {
        var transport = new FakeTransport().ReplyToEverything("No match for the domain.");
        using var client = Build(transport);

        var results = await client.CheckAsync(new[] { "monovm" });

        Assert.Equal(2, results.Count);
        Assert.True(results.ContainsKey("monovm.com"));
        Assert.True(results.ContainsKey("monovm.co.uk"));
    }

    [Fact]
    public async Task Looks_a_duplicate_up_only_once()
    {
        var transport = new FakeTransport().ReplyToEverything(Fixtures.ComRecord);
        using var client = Build(transport);

        var results = await client.CheckAsync(new[] { "example.com", "EXAMPLE.COM", "https://example.com/x" });

        Assert.Single(results);
        Assert.Equal(1, transport.CallCount);
    }

    [Fact]
    public async Task Returns_results_in_the_order_they_were_asked_for()
    {
        var transport = new FakeTransport().ReplyToEverything("No match for the domain.");
        using var client = Build(transport);

        var order = new List<string>();
        await foreach (var result in client.LookupManyAsync(new[] { "c.com", "a.com", "b.com" }))
        {
            order.Add(result.Name);
        }

        Assert.Equal(new[] { "c.com", "a.com", "b.com" }, order);
    }

    [Fact]
    public async Task Rejects_a_single_lookup_with_no_suffix()
    {
        var transport = new FakeTransport();
        using var client = Build(transport);

        var result = await client.LookupAsync("monovm");

        Assert.Equal(DomainAvailabilityStatus.Invalid, result.Status);
        Assert.Equal(0, transport.CallCount);
    }

    [Fact]
    public async Task Sends_punycode_to_the_wire_by_default()
    {
        var transport = new FakeTransport().ReplyToEverything(Fixtures.ComRecord);
        using var client = Build(transport);

        await client.LookupAsync("bücher.com");

        Assert.Equal("xn--bcher-kva.com", transport.Queries[0].QueryText);
    }

    [Fact]
    public async Task Sends_unicode_to_the_registries_that_want_it()
    {
        var transport = new FakeTransport().ReplyToEverything("Status: connect");
        using var client = Build(transport, builder => builder.Configure(options =>
        {
            options.UnicodeQueryTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".de" };
        }));

        await client.LookupAsync("münchen.de");

        Assert.Equal("münchen.de", transport.Queries[0].QueryText);
    }

    [Fact]
    public async Task Keeps_the_form_the_caller_used_in_the_result()
    {
        var transport = new FakeTransport().ReplyToEverything(Fixtures.ComRecord);
        using var client = Build(transport);

        var result = await client.LookupAsync("bücher.com");

        Assert.Equal("bücher.com", result.Name);
        Assert.Equal("xn--bcher-kva.com", result.Domain?.Ascii);
    }

    [Fact]
    public async Task IsAvailableAsync_is_false_for_anything_that_is_not_a_clear_yes()
    {
        var transport = new FakeTransport()
            .Reply("free123.com", "No match for \"FREE123.COM\".")
            .Reply("example.com", Fixtures.ComRecord)
            .Throw("broken.com", new WhoisConnectionException("unreachable"));

        using var client = Build(transport);

        Assert.True(await client.IsAvailableAsync("free123.com"));
        Assert.False(await client.IsAvailableAsync("example.com"));
        Assert.False(await client.IsAvailableAsync("broken.com"));
    }
}

public class WhoisOptionsTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Rejects_a_non_positive_timeout(int seconds)
    {
        var options = new WhoisOptions { Whois43Timeout = TimeSpan.FromSeconds(seconds) };
        Assert.Throws<WhoisDefinitionException>(() => options.Validate());
    }

    [Fact]
    public void Rejects_an_empty_popular_suffix_list()
    {
        var options = new WhoisOptions { PopularTlds = new List<string>() };
        Assert.Throws<WhoisDefinitionException>(() => options.Validate());
    }

    [Fact]
    public void Rejects_a_configuration_that_can_serve_nothing()
    {
        var options = new WhoisOptions { UseBundledDefinitions = false };
        Assert.Throws<WhoisDefinitionException>(() => options.Validate());
    }

    [Fact]
    public void Normalises_the_popular_suffixes()
    {
        var options = new WhoisOptions { PopularTlds = new List<string> { "COM", ".net.", "org", "com" } };

        Assert.Equal(new[] { ".com", ".net", ".org" }, options.NormalizedPopularTlds());
    }
}

public class DependencyInjectionTests
{
    [Fact]
    public void Registers_a_single_client_behind_every_interface()
    {
        var services = new ServiceCollection();
        services.AddWhois(options => options.MaxDegreeOfParallelism = 3);

        using var provider = services.BuildServiceProvider();

        var client = provider.GetRequiredService<IWhoisClient>();
        Assert.Same(client, provider.GetRequiredService<IWhoisLookup>());
        Assert.Same(client, provider.GetRequiredService<IDomainAvailabilityChecker>());
        Assert.Same(client, provider.GetRequiredService<WhoisClient>());
        Assert.Equal(3, provider.GetRequiredService<WhoisClient>().Options.MaxDegreeOfParallelism);
    }

    [Fact]
    public void Lets_a_caller_replace_a_collaborator()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IWhoisServerRegistry>(TestServers.Registry());
        services.AddWhois();

        using var provider = services.BuildServiceProvider();

        Assert.Equal(5, provider.GetRequiredService<IWhoisClient>().Servers.SupportedTlds.Count);
    }

    [Fact]
    public void Serves_the_bundled_table_by_default()
    {
        var services = new ServiceCollection();
        services.AddWhois();

        using var provider = services.BuildServiceProvider();

        Assert.True(provider.GetRequiredService<IWhoisClient>().Servers.Supports(".com"));
    }
}

public class StatusWireFormatTests
{
    [Theory]
    [InlineData(DomainAvailabilityStatus.Available, "available")]
    [InlineData(DomainAvailabilityStatus.Registered, "unavailable")]
    [InlineData(DomainAvailabilityStatus.Premium, "premium")]
    [InlineData(DomainAvailabilityStatus.Invalid, "invalid")]
    [InlineData(DomainAvailabilityStatus.Error, "error")]
    [InlineData(DomainAvailabilityStatus.Unknown, "unknown")]
    public void Matches_the_php_packages_wording(DomainAvailabilityStatus status, string expected)
    {
        Assert.Equal(expected, status.ToWireString());
    }
}

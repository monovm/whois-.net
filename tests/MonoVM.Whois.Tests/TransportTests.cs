using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;
using MonoVM.Whois.Transport;
using MonoVM.Whois.Transport.Decorators;
using Xunit;

namespace MonoVM.Whois.Tests;

public class MemoryCacheTests
{
    [Fact]
    public void Serves_an_entry_until_it_expires()
    {
        var clock = new TestClock();
        var cache = new MemoryWhoisResponseCache(16, clock);
        var response = Response("hello");

        cache.Set("k", response, TimeSpan.FromMinutes(5));
        Assert.True(cache.TryGet("k", out var hit));
        Assert.Equal("hello", hit!.Text);

        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.False(cache.TryGet("k", out _));
    }

    [Fact]
    public void Stays_within_its_capacity()
    {
        var cache = new MemoryWhoisResponseCache(8);

        for (var i = 0; i < 100; i++)
        {
            cache.Set($"k{i}", Response($"r{i}"), TimeSpan.FromMinutes(5));
        }

        Assert.True(cache.Count <= 8, $"capacity was 8 but the cache holds {cache.Count}");
    }

    private static WhoisResponse Response(string text)
        => new WhoisResponse(DomainName.Parse("example.com"), text, WhoisProtocol.Whois43, "whois.test", TimeSpan.Zero);
}

public class CachingTransportTests
{
    [Fact]
    public async Task Asks_the_registry_once_for_the_same_question()
    {
        var inner = new FakeTransport().ReplyToEverything("Domain Name: example.com");
        var options = new WhoisOptions { CacheLifetime = TimeSpan.FromMinutes(5) };
        var transport = new CachingWhoisTransport(inner, new MemoryWhoisResponseCache(), options);
        var query = Query();

        var first = await transport.QueryAsync(query);
        var second = await transport.QueryAsync(query);

        Assert.Equal(1, inner.CallCount);
        Assert.False(first.FromCache);
        Assert.True(second.FromCache);
    }

    [Fact]
    public async Task Does_not_cache_a_failure()
    {
        var inner = new FlakyTransport(1, () => new WhoisServerException("rate limited"));
        var options = new WhoisOptions { CacheLifetime = TimeSpan.FromMinutes(5) };
        var transport = new CachingWhoisTransport(inner, new MemoryWhoisResponseCache(), options);

        await Assert.ThrowsAsync<WhoisServerException>(() => transport.QueryAsync(Query()));
        var second = await transport.QueryAsync(Query());

        Assert.False(second.FromCache);
        Assert.Equal(2, inner.Attempts);
    }

    private static WhoisQuery Query()
        => new WhoisQuery(DomainName.Parse("example.com"), TestServers.Com, "example.com");
}

public class RetryingTransportTests
{
    private static readonly WhoisOptions Options = new WhoisOptions
    {
        MaxRetryAttempts = 2,
        RetryDelay = TimeSpan.Zero,
    };

    [Fact]
    public async Task Retries_a_connection_failure_and_succeeds()
    {
        var inner = new FlakyTransport(2, () => new WhoisConnectionException("unreachable"));
        var transport = new RetryingWhoisTransport(inner, Options);

        var response = await transport.QueryAsync(Query());

        Assert.Equal(3, inner.Attempts);
        Assert.Contains("example.com", response.Text);
    }

    [Fact]
    public async Task Gives_up_after_the_configured_number_of_attempts()
    {
        var inner = new FlakyTransport(99, () => new WhoisConnectionException("unreachable"));
        var transport = new RetryingWhoisTransport(inner, Options);

        await Assert.ThrowsAsync<WhoisConnectionException>(() => transport.QueryAsync(Query()));
        Assert.Equal(3, inner.Attempts);
    }

    [Fact]
    public async Task Does_not_retry_a_refusal_that_will_not_clear()
    {
        var inner = new FlakyTransport(99, () => new WhoisServerException("blocked") { IsTransient = false });
        var transport = new RetryingWhoisTransport(inner, Options);

        await Assert.ThrowsAsync<WhoisServerException>(() => transport.QueryAsync(Query()));
        Assert.Equal(1, inner.Attempts);
    }

    private static WhoisQuery Query()
        => new WhoisQuery(DomainName.Parse("example.com"), TestServers.Com, "example.com");
}

public class ReferralFollowingTests
{
    [Fact]
    public void Finds_the_registrar_server_named_in_a_thin_reply()
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "whois.verisign-grs.com" };

        Assert.Equal(
            "whois.registrar.test",
            ReferralFollowingWhoisTransport.FindReferral(Fixtures.ComRecord, visited));
    }

    [Fact]
    public void Ignores_a_referral_it_has_already_followed()
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "whois.registrar.test" };

        Assert.Null(ReferralFollowingWhoisTransport.FindReferral(Fixtures.ComRecord, visited));
    }

    [Fact]
    public void Ignores_a_url_in_the_referral_field()
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Assert.Null(ReferralFollowingWhoisTransport.FindReferral(
            "Registrar WHOIS Server: https://whois.registrar.test/lookup", visited));
    }

    [Fact]
    public async Task Attaches_the_registrar_reply_without_replacing_the_registrys()
    {
        var inner = new HostAwareTransport();
        var transport = new ReferralFollowingWhoisTransport(inner, new WhoisOptions { MaxReferralDepth = 2 });

        var response = await transport.QueryAsync(
            new WhoisQuery(DomainName.Parse("example.com"), TestServers.Com, "example.com"));

        Assert.Contains("Registry Domain ID", response.Text);
        Assert.Single(response.Referrals);
        Assert.Contains("Registrant Organization", response.Referrals[0].Text);
    }

    [Fact]
    public async Task A_registrar_that_refuses_does_not_spoil_the_lookup()
    {
        var inner = new HostAwareTransport(failReferral: true);
        var transport = new ReferralFollowingWhoisTransport(inner, new WhoisOptions { MaxReferralDepth = 2 });

        var response = await transport.QueryAsync(
            new WhoisQuery(DomainName.Parse("example.com"), TestServers.Com, "example.com"));

        Assert.Contains("Registry Domain ID", response.Text);
        Assert.Empty(response.Referrals);
    }

    private sealed class HostAwareTransport : IWhoisTransport
    {
        private readonly bool _failReferral;

        public HostAwareTransport(bool failReferral = false) => _failReferral = failReferral;

        public Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
        {
            if (query.Server.Host == "whois.registrar.test")
            {
                if (_failReferral)
                {
                    throw new WhoisServerException("blocked", query.Server.Host);
                }

                return Task.FromResult(new WhoisResponse(
                    query.Domain, Fixtures.RegistrarRecord, WhoisProtocol.Whois43, query.Server.Host, TimeSpan.Zero));
            }

            return Task.FromResult(new WhoisResponse(
                query.Domain, Fixtures.ComRecord, WhoisProtocol.Whois43, query.Server.Host, TimeSpan.Zero));
        }
    }
}

public class HostRateLimiterTests
{
    [Fact]
    public async Task Spaces_out_queries_to_the_same_host()
    {
        var limiter = new HostRateLimiter();
        var delay = TimeSpan.FromMilliseconds(120);
        var stopwatch = Stopwatch.StartNew();

        await limiter.WaitAsync("whois.test", delay);
        await limiter.WaitAsync("whois.test", delay);

        stopwatch.Stop();
        Assert.True(
            stopwatch.Elapsed >= TimeSpan.FromMilliseconds(90),
            $"expected the second query to wait, but only {stopwatch.ElapsedMilliseconds}ms passed");
    }

    [Fact]
    public async Task Does_not_make_one_host_wait_for_another()
    {
        var limiter = new HostRateLimiter();
        var delay = TimeSpan.FromMilliseconds(500);
        var stopwatch = Stopwatch.StartNew();

        await limiter.WaitAsync("a.test", delay);
        await limiter.WaitAsync("b.test", delay);

        stopwatch.Stop();
        Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(400));
    }
}

public class Whois43DecodingTests
{
    [Fact]
    public void Reads_utf8()
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes("Registrant: Müller GmbH");
        Assert.Equal("Registrant: Müller GmbH", Whois43Transport.Decode(bytes));
    }

    [Fact]
    public void Falls_back_to_latin1_rather_than_mangling_the_text()
    {
        var bytes = System.Text.Encoding.GetEncoding(28591).GetBytes("Registrant: Müller GmbH");

        // Decoded as UTF-8 this would be a replacement character; the fallback keeps the umlaut.
        Assert.Equal("Registrant: Müller GmbH", Whois43Transport.Decode(bytes));
    }
}

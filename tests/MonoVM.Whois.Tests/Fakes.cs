using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Tests;

/// <summary>
/// A transport that answers from a script instead of the network.
/// </summary>
/// <remarks>
/// The whole point of putting the wire behind <see cref="IWhoisTransport"/> is that the rest of the
/// library can be tested without one. Every behavioural test in this suite runs offline.
/// </remarks>
internal sealed class FakeTransport : IWhoisTransport, IWhoisTransportFactory
{
    private readonly Dictionary<string, Func<WhoisQuery, WhoisResponse>> _answers =
        new Dictionary<string, Func<WhoisQuery, WhoisResponse>>(StringComparer.OrdinalIgnoreCase);

    private Func<WhoisQuery, WhoisResponse>? _fallback;

    public List<WhoisQuery> Queries { get; } = new List<WhoisQuery>();

    public int CallCount => Queries.Count;

    public FakeTransport Reply(string domain, string text, WhoisProtocol protocol = WhoisProtocol.Whois43, int? httpStatus = null)
    {
        _answers[domain] = query => new WhoisResponse(
            query.Domain, text, protocol, query.Server.Host, TimeSpan.FromMilliseconds(1), httpStatus);
        return this;
    }

    public FakeTransport Throw(string domain, WhoisException exception)
    {
        _answers[domain] = _ => throw exception;
        return this;
    }

    public FakeTransport ReplyToEverything(string text)
    {
        _fallback = query => new WhoisResponse(
            query.Domain, text, query.Server.Protocol, query.Server.Host, TimeSpan.FromMilliseconds(1));
        return this;
    }

    public Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        Queries.Add(query);

        if (_answers.TryGetValue(query.Domain.Ascii, out var answer))
        {
            return Task.FromResult(answer(query));
        }

        if (_fallback is not null)
        {
            return Task.FromResult(_fallback(query));
        }

        throw new EmptyWhoisResponseException($"No canned reply for {query.Domain.Ascii}.", query.Server.Host);
    }

    public IWhoisTransport Create(WhoisServerDefinition server) => this;
}

/// <summary>A transport that fails a set number of times before succeeding.</summary>
internal sealed class FlakyTransport : IWhoisTransport
{
    private readonly int _failures;
    private readonly Func<WhoisException> _exception;
    private readonly string _text;

    public FlakyTransport(int failures, Func<WhoisException> exception, string text = "Domain Name: example.com")
    {
        _failures = failures;
        _exception = exception;
        _text = text;
    }

    public int Attempts { get; private set; }

    public Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default)
    {
        Attempts++;

        if (Attempts <= _failures)
        {
            throw _exception();
        }

        return Task.FromResult(new WhoisResponse(
            query.Domain, _text, WhoisProtocol.Whois43, query.Server.Host, TimeSpan.Zero));
    }
}

/// <summary>A clock the tests move by hand.</summary>
internal sealed class TestClock : MonoVM.Whois.Internal.IClock
{
    public DateTimeOffset UtcNow { get; set; } = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public void Advance(TimeSpan by) => UtcNow += by;
}

/// <summary>Server definitions the tests build against.</summary>
internal static class TestServers
{
    public static WhoisServerDefinition Com { get; } = WhoisServerDefinition.Create(
        ".com", "socket://whois.verisign-grs.com", available: "No match for", source: "test");

    public static WhoisServerDefinition CoUk { get; } = WhoisServerDefinition.Create(
        ".co.uk", "socket://whois.nic.uk", available: "No match", source: "test");

    public static WhoisServerDefinition Shop { get; } = WhoisServerDefinition.Create(
        ".shop", "https://rdap.gmoregistry.net/rdap/domain/", source: "test");

    public static WhoisServerDefinition Mc { get; } = WhoisServerDefinition.Create(
        ".mc", "socket://whois.nic.mc", availableWhenEmpty: true, source: "test");

    public static WhoisServerDefinition De { get; } = WhoisServerDefinition.Create(
        ".de", "socket://whois.denic.de", available: "Status: free", source: "test");

    public static IWhoisServerRegistry Registry() => new MonoVM.Whois.Registry.WhoisServerRegistry(
        new[] { Com, CoUk, Shop, Mc, De }, "test");
}

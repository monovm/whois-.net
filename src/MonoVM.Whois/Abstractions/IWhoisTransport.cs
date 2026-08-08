using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>Puts a query on the wire and brings the reply back, uninterpreted.</summary>
/// <remarks>
/// <para>
/// One implementation per protocol — port 43 and RDAP — plus a set of decorators that add caching,
/// retries, rate limiting, referral following and logging without either protocol knowing about
/// them. A caller that wants a different protocol, or a recorded transport for tests, implements
/// this interface and changes nothing else.
/// </para>
/// <para>
/// Implementations must not interpret the reply. Deciding what a reply means is the analyzer's job,
/// and keeping the two apart is what makes both testable offline.
/// </para>
/// </remarks>
public interface IWhoisTransport
{
    /// <summary>Sends <paramref name="query"/> and returns the raw reply.</summary>
    /// <exception cref="Exceptions.WhoisConnectionException">The server could not be reached.</exception>
    /// <exception cref="Exceptions.WhoisServerException">The server refused to answer.</exception>
    /// <exception cref="Exceptions.EmptyWhoisResponseException">The server answered with nothing.</exception>
    Task<WhoisResponse> QueryAsync(WhoisQuery query, CancellationToken cancellationToken = default);
}

/// <summary>Chooses and assembles the transport stack for a given registry.</summary>
public interface IWhoisTransportFactory
{
    /// <summary>Builds the transport pipeline for <paramref name="server"/>.</summary>
    IWhoisTransport Create(WhoisServerDefinition server);
}

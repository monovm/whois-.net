using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>Retrieves registration data for a domain.</summary>
public interface IWhoisLookup
{
    /// <summary>Looks one name up and returns everything the registry said about it.</summary>
    /// <param name="domain">A domain name, or anything a user might paste that contains one.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    Task<WhoisLookupResult> LookupAsync(string domain, CancellationToken cancellationToken = default);

    /// <summary>Looks up an already-parsed name.</summary>
    Task<WhoisLookupResult> LookupAsync(DomainName domain, CancellationToken cancellationToken = default);
}

/// <summary>Answers the narrower question of whether a name can be registered.</summary>
/// <remarks>
/// Separate from <see cref="IWhoisLookup"/> so that the many callers who only want a yes or no do
/// not have to depend on the record model to get one.
/// </remarks>
public interface IDomainAvailabilityChecker
{
    /// <summary>True when the registry says the name is free to register.</summary>
    /// <remarks>
    /// False for anything that is not a clear yes, failures included. Use
    /// <see cref="CheckAsync(IEnumerable{string}, CancellationToken)"/> when the difference between
    /// "taken" and "could not tell" matters.
    /// </remarks>
    Task<bool> IsAvailableAsync(string domain, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks several names at once and reports the status of each.
    /// </summary>
    /// <param name="domains">
    /// Names to check. A bare label such as <c>"monovm"</c> is expanded across
    /// <see cref="Configuration.WhoisOptions.PopularTlds"/>; duplicates are looked up once.
    /// </param>
    /// <param name="cancellationToken">Cancels the remaining lookups.</param>
    Task<IReadOnlyDictionary<string, DomainAvailabilityStatus>> CheckAsync(
        IEnumerable<string> domains,
        CancellationToken cancellationToken = default);
}

/// <summary>The library's entry point: lookups, availability checks and the server table.</summary>
public interface IWhoisClient : IWhoisLookup, IDomainAvailabilityChecker
{
    /// <summary>The suffix table this client is working from.</summary>
    IWhoisServerRegistry Servers { get; }

    /// <summary>
    /// Looks up several names, yielding each result as it completes and in the order asked.
    /// </summary>
    /// <param name="domains">
    /// Names to look up. A bare label is expanded across the configured popular suffixes.
    /// </param>
    /// <param name="cancellationToken">Cancels the remaining lookups.</param>
    IAsyncEnumerable<WhoisLookupResult> LookupManyAsync(
        IEnumerable<string> domains,
        CancellationToken cancellationToken = default);
}

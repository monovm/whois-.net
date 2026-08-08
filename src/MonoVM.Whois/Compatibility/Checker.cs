using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Compatibility;

/// <summary>Options accepted by <see cref="Checker"/>.</summary>
public sealed class CheckerOptions
{
    /// <summary>Suffixes tried when a domain is given without one.</summary>
    public IList<string>? PopularTlds { get; set; }

    /// <summary>Applies these options over a fresh set of library options.</summary>
    internal WhoisOptions ToWhoisOptions()
    {
        var options = new WhoisOptions();

        if (PopularTlds is { Count: > 0 })
        {
            options.PopularTlds = new List<string>(PopularTlds);
        }

        return options;
    }
}

/// <summary>
/// The bulk availability check behind one static call, for scripts and quick checks.
/// </summary>
/// <remarks>
/// <para>
/// One call, no client to construct, and a dictionary of lower-case status strings back. New code
/// should prefer <see cref="IWhoisClient"/>, which is async, cancellable, and says what went wrong
/// when something did.
/// </para>
/// <para>
/// A lookup that fails reports <c>error</c>, never <c>available</c>: a rate-limited server has
/// told you nothing about the domain.
/// </para>
/// </remarks>
public static class Checker
{
    /// <summary>Checks one domain.</summary>
    /// <param name="domain">A domain name; the suffix is optional.</param>
    /// <param name="options">Optional settings.</param>
    /// <returns>A map of full domain name to status.</returns>
    public static IReadOnlyDictionary<string, string> Whois(string domain, CheckerOptions? options = null)
        => Whois(new[] { domain }, options);

    /// <summary>Checks several domains.</summary>
    /// <param name="domains">Domain names; the suffix is optional for each.</param>
    /// <param name="options">Optional settings.</param>
    /// <returns>A map of full domain name to status.</returns>
    public static IReadOnlyDictionary<string, string> Whois(
        IEnumerable<string> domains,
        CheckerOptions? options = null)
    {
        // Off the caller's context on purpose: this is a blocking wrapper around async work, and
        // running it inline would deadlock under a single-threaded synchronisation context.
        return Task.Run(() => WhoisAsync(domains, options)).GetAwaiter().GetResult();
    }

    /// <inheritdoc cref="Whois(IEnumerable{string}, CheckerOptions?)"/>
    public static async Task<IReadOnlyDictionary<string, string>> WhoisAsync(
        IEnumerable<string> domains,
        CheckerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (domains is null)
        {
            throw new ArgumentNullException(nameof(domains));
        }

        using var client = new WhoisClient(options?.ToWhoisOptions() ?? new WhoisOptions());
        var statuses = await client.CheckAsync(domains, cancellationToken).ConfigureAwait(false);

        var results = new Dictionary<string, string>(statuses.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in statuses)
        {
            results[entry.Key] = entry.Value.ToWireString();
        }

        return results;
    }

    /// <inheritdoc cref="Whois(string, CheckerOptions?)"/>
    public static Task<IReadOnlyDictionary<string, string>> WhoisAsync(
        string domain,
        CheckerOptions? options = null,
        CancellationToken cancellationToken = default)
        => WhoisAsync(new[] { domain }, options, cancellationToken);
}

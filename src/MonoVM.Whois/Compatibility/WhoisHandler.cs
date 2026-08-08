using System;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Detection;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Compatibility;

/// <summary>
/// A single-domain lookup behind one static call, for scripts and quick checks.
/// </summary>
/// <remarks>
/// <para>
/// A thin wrapper over <see cref="WhoisLookupResult"/>. New code should use
/// <see cref="WhoisClient.LookupAsync(string, CancellationToken)"/>,
/// which returns the same information plus the parsed record and the reasoning behind the verdict.
/// </para>
/// <para>
/// Two behaviours worth knowing, both in the same safe direction:
/// </para>
/// <list type="bullet">
///   <item><description>a premium or reserved name reports <see cref="IsPremium"/>, and <see cref="IsAvailable"/> is false;</description></item>
///   <item><description>a server that refuses to answer reports <see cref="IsValid"/> false rather than an availability verdict.</description></item>
/// </list>
/// </remarks>
public sealed class WhoisHandler
{
    private WhoisHandler(WhoisLookupResult result)
    {
        Result = result;
        Tld = result.Domain?.Tld ?? string.Empty;
        Sld = result.Domain?.Sld ?? string.Empty;
    }

    /// <summary>The full result this handler wraps.</summary>
    public WhoisLookupResult Result { get; }

    /// <summary>The top-level suffix, including its leading dot.</summary>
    public string Tld { get; }

    /// <summary>The second-level label.</summary>
    public string Sld { get; }

    /// <summary>The parsed record, when the name is registered.</summary>
    public WhoisRecord? Record => Result.Record;

    /// <summary>How the verdict was reached.</summary>
    public AvailabilityVerdict? Verdict => Result.Verdict;

    /// <summary>Looks a domain up, blocking until it completes.</summary>
    public static WhoisHandler Whois(string domain, WhoisOptions? options = null)
        => Task.Run(() => WhoisAsync(domain, options)).GetAwaiter().GetResult();

    /// <summary>Looks a domain up.</summary>
    public static async Task<WhoisHandler> WhoisAsync(
        string domain,
        WhoisOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (domain is null)
        {
            throw new ArgumentNullException(nameof(domain));
        }

        using var client = new WhoisClient(options ?? new WhoisOptions());
        var result = await client.LookupAsync(domain, cancellationToken).ConfigureAwait(false);
        return new WhoisHandler(result);
    }

    /// <summary>Returns the top-level suffix.</summary>
    public string GetTld() => Tld;

    /// <summary>Returns the second-level label.</summary>
    public string GetSld() => Sld;

    /// <summary>True when the domain is free to register.</summary>
    public bool IsAvailable() => Result.IsAvailable;

    /// <summary>True when the registry is holding the name back as premium or reserved.</summary>
    public bool IsPremium() => Result.IsPremium;

    /// <summary>True when the domain could be looked up and the registry gave a verdict.</summary>
    public bool IsValid() => Result.Succeeded;

    /// <summary>The registry's message: the record, or a sentence explaining the outcome.</summary>
    public string GetWhoisMessage() => Result.Message;

    /// <summary>The registry's reply verbatim, or the message when there was no reply.</summary>
    public string GetRawWhoisMessage() => Result.RawText ?? Result.Message;

    /// <summary>The status as a lower-case string: <c>available</c>, <c>unavailable</c>, and so on.</summary>
    public string GetStatus() => Result.Status.ToWireString();

    /// <inheritdoc />
    public override string ToString() => Result.ToString();
}

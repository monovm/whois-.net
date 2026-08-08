using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>
/// Answers "who serves this suffix, and where does this host name split?".
/// </summary>
/// <remarks>
/// The two questions belong together because the second cannot be answered without the first:
/// <c>example.co.uk</c> splits after <c>example</c> only because <c>.co.uk</c> is a known suffix,
/// while <c>example.co.com</c> splits after <c>example.co</c> because <c>.co.com</c> is not.
/// </remarks>
public interface IWhoisServerRegistry
{
    /// <summary>Every suffix this registry can serve, sorted, each with its leading dot.</summary>
    IReadOnlyCollection<string> SupportedTlds { get; }

    /// <summary>True when a server is configured for <paramref name="tld"/>.</summary>
    bool Supports(string? tld);

    /// <summary>Looks up the definition for <paramref name="tld"/>.</summary>
    bool TryGet(string? tld, [NotNullWhen(true)] out WhoisServerDefinition? definition);

    /// <summary>
    /// Returns the longest known suffix of <paramref name="host"/>, or <see langword="null"/> when
    /// none of its suffixes is known.
    /// </summary>
    /// <example>
    /// <c>www.example.co.uk</c> yields <c>.co.uk</c>, not <c>.uk</c>.
    /// </example>
    string? FindLongestSuffix(string host);
}

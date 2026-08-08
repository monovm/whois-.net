using System.Diagnostics.CodeAnalysis;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>Turns user input into a <see cref="DomainName"/> split at the right place.</summary>
public interface IDomainNameParser
{
    /// <summary>
    /// Normalises <paramref name="input"/> — scheme, credentials, port, path, case, stray dots —
    /// and splits it into a registrable name using the registry's suffix list.
    /// </summary>
    /// <param name="input">Anything a user might paste: <c>example.com</c>, <c>WWW.Example.CO.UK</c>, <c>https://example.com/pricing?x=1</c>.</param>
    /// <param name="domain">The parsed name.</param>
    /// <param name="error">Why parsing failed, when it did.</param>
    /// <returns>True when <paramref name="input"/> yielded a name that could be looked up.</returns>
    bool TryParse(string? input, [NotNullWhen(true)] out DomainName? domain, out string? error);

    /// <summary>Parses <paramref name="input"/> or throws.</summary>
    /// <exception cref="Exceptions.InvalidDomainException"><paramref name="input"/> is not usable.</exception>
    DomainName Parse(string input);
}

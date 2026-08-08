using System;
using System.Diagnostics.CodeAnalysis;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Registry;

/// <summary>
/// Splits user input into a registrable name, using the registry's suffix list to decide where the
/// split goes.
/// </summary>
/// <remarks>
/// Accepts what people actually paste — a URL, mixed case, a trailing root dot, a subdomain, a port
/// — and reduces it to the name that can be looked up. <c>https://WWW.Example.CO.UK/pricing</c>
/// becomes <c>example.co.uk</c>.
/// </remarks>
public sealed class DomainNameParser : IDomainNameParser
{
    private readonly IWhoisServerRegistry _registry;

    /// <summary>Creates a parser over <paramref name="registry"/>.</summary>
    public DomainNameParser(IWhoisServerRegistry registry)
        => _registry = registry ?? throw new ArgumentNullException(nameof(registry));

    /// <inheritdoc />
    public bool TryParse(string? input, [NotNullWhen(true)] out DomainName? domain, out string? error)
    {
        domain = null;
        error = null;

        var normalized = DomainNameNormalizer.Normalize(input);
        if (normalized.Length == 0)
        {
            error = "the input contains no host name";
            return false;
        }

        // "co.uk" is a public suffix, not a domain, and nobody can register it. Only checked for
        // multi-label input: a single label such as "shop" is a name someone wants to look up, even
        // though ".shop" is also a suffix.
        if (normalized.IndexOf('.') > 0 && _registry.Supports(normalized))
        {
            error = $"'{normalized}' is a bare suffix, not a domain name";
            return false;
        }

        var suffix = _registry.FindLongestSuffix(normalized);

        if (suffix is not null)
        {
            // The label immediately before the suffix is the registrable one; anything to the left
            // of that is a subdomain and plays no part in a WHOIS lookup.
            var stem = normalized.Substring(0, normalized.Length - suffix.Length);
            var lastDot = stem.LastIndexOf('.');
            var sld = lastDot < 0 ? stem : stem.Substring(lastDot + 1);

            if (sld.Length == 0)
            {
                error = $"'{normalized}' is a bare suffix, not a domain name";
                return false;
            }

            domain = DomainName.FromParts(sld, suffix);
        }
        else
        {
            // No suffix in the table matches. Fall back to a split at the first dot so the caller
            // can report the suffix as unsupported rather than the input as unreadable.
            if (!DomainName.TryParse(normalized, out var fallback))
            {
                error = $"'{normalized}' could not be read as a domain name";
                return false;
            }

            domain = fallback;
        }

        if (domain.HasTld && !domain.IsWellFormed)
        {
            error = $"'{domain.Ascii}' is not a well-formed host name";
            domain = null;
            return false;
        }

        if (!domain.HasTld && !DomainNameNormalizer.IsValidHostName(domain.AsciiSld))
        {
            error = $"'{domain.Input}' is not a well-formed domain label";
            domain = null;
            return false;
        }

        return true;
    }

    /// <inheritdoc />
    public DomainName Parse(string input)
    {
        if (TryParse(input, out var domain, out var error))
        {
            return domain;
        }

        throw new InvalidDomainException($"Unable to look up '{input}': {error}.", input);
    }
}

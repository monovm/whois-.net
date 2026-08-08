using System;
using MonoVM.Whois.Internal;

namespace MonoVM.Whois.Model;

/// <summary>
/// An immutable, validated domain name split into its second-level label and its top-level suffix.
/// </summary>
/// <remarks>
/// <para>
/// This is a value object: two instances describing the same name are equal, and nothing about an
/// instance can change after construction. It keeps both the Unicode and the punycode (ACE) forms
/// because the two are needed in different places — registries are queried in punycode (with a few
/// documented exceptions), while results are reported back in whatever form the caller used.
/// </para>
/// <para>
/// The suffix cannot be worked out from the string alone: <c>example.co.uk</c> is registered under
/// <c>.co.uk</c> while <c>example.co.com</c> is registered under <c>.com</c>. Splitting is therefore
/// the job of <see cref="Abstractions.IDomainNameParser"/>, which matches the longest known suffix
/// against the loaded server definitions; this type only carries the outcome.
/// </para>
/// </remarks>
public sealed class DomainName : IEquatable<DomainName>
{
    private DomainName(string input, string sld, string tld)
    {
        Input = input;
        Sld = sld;
        Tld = tld;
        Unicode = DomainNameNormalizer.ToUnicode(sld + tld);
        Ascii = DomainNameNormalizer.ToAscii(sld + tld);
        AsciiSld = DomainNameNormalizer.ToAscii(sld);
        AsciiTld = DomainNameNormalizer.ToAscii(tld);
    }

    /// <summary>The string the caller supplied, trimmed and lower-cased but otherwise untouched.</summary>
    public string Input { get; }

    /// <summary>The second-level label, e.g. <c>monovm</c> in <c>monovm.co.uk</c>.</summary>
    public string Sld { get; }

    /// <summary>
    /// The top-level suffix including its leading dot, e.g. <c>.co.uk</c>. Empty when the input
    /// carried no suffix at all (<c>"monovm"</c>).
    /// </summary>
    public string Tld { get; }

    /// <summary>The second-level label in punycode form.</summary>
    public string AsciiSld { get; }

    /// <summary>The suffix in punycode form, including its leading dot.</summary>
    public string AsciiTld { get; }

    /// <summary>The full name in Unicode form, e.g. <c>münchen.de</c>.</summary>
    public string Unicode { get; }

    /// <summary>The full name in punycode form, e.g. <c>xn--mnchen-3ya.de</c>.</summary>
    public string Ascii { get; }

    /// <summary>True when the name carries a suffix.</summary>
    public bool HasTld => Tld.Length > 0;

    /// <summary>True when the Unicode and punycode forms differ, i.e. this is an IDN.</summary>
    public bool IsInternationalized => !string.Equals(Unicode, Ascii, StringComparison.Ordinal);

    /// <summary>True when every label of the punycode form is a legal DNS label.</summary>
    public bool IsWellFormed => DomainNameNormalizer.IsValidHostName(Ascii);

    /// <summary>
    /// Builds a name from an already-split second-level label and suffix. The suffix may be given
    /// with or without its leading dot.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="sld"/> is empty.</exception>
    public static DomainName FromParts(string sld, string? tld)
    {
        if (string.IsNullOrWhiteSpace(sld))
        {
            throw new ArgumentException("The second-level label must not be empty.", nameof(sld));
        }

        var normalizedSld = DomainNameNormalizer.Normalize(sld);
        var normalizedTld = NormalizeSuffix(tld);

        return new DomainName(normalizedSld + normalizedTld, normalizedSld, normalizedTld);
    }

    /// <summary>
    /// Splits <paramref name="input"/> at its first dot, without consulting any suffix list.
    /// </summary>
    /// <remarks>
    /// Useful for tests and for callers that already know the name is a plain <c>label.tld</c>.
    /// Prefer <see cref="Abstractions.IDomainNameParser"/>, which knows about multi-label suffixes
    /// such as <c>.co.uk</c> and strips subdomains.
    /// </remarks>
    public static DomainName Parse(string input)
    {
        if (!TryParse(input, out var domain))
        {
            throw new ArgumentException($"'{input}' is not a usable domain name.", nameof(input));
        }

        return domain;
    }

    /// <inheritdoc cref="Parse(string)"/>
    public static bool TryParse(string? input, out DomainName domain)
    {
        domain = null!;
        var normalized = DomainNameNormalizer.Normalize(input);
        if (normalized.Length == 0)
        {
            return false;
        }

        var dot = normalized.IndexOf('.');
        var sld = dot < 0 ? normalized : normalized.Substring(0, dot);
        var tld = dot < 0 ? string.Empty : normalized.Substring(dot);

        if (sld.Length == 0)
        {
            return false;
        }

        domain = new DomainName(normalized, sld, tld);
        return true;
    }

    /// <summary>Returns the same name under a different suffix, e.g. <c>monovm.com</c> to <c>monovm.net</c>.</summary>
    public DomainName WithTld(string tld) => FromParts(Sld, tld);

    /// <summary>Normalises a suffix to lower case with exactly one leading dot; empty stays empty.</summary>
    internal static string NormalizeSuffix(string? tld)
    {
        if (string.IsNullOrWhiteSpace(tld))
        {
            return string.Empty;
        }

        var trimmed = tld!.Trim().Trim('.').ToLowerInvariant();
        return trimmed.Length == 0 ? string.Empty : "." + trimmed;
    }

    /// <inheritdoc />
    public bool Equals(DomainName? other)
        => other is not null && string.Equals(Ascii, other.Ascii, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as DomainName);

    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Ascii);

    /// <inheritdoc />
    public override string ToString() => Unicode;

    public static bool operator ==(DomainName? left, DomainName? right)
        => left is null ? right is null : left.Equals(right);

    public static bool operator !=(DomainName? left, DomainName? right) => !(left == right);
}

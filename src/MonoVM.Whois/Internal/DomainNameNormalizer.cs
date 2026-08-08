using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace MonoVM.Whois.Internal;

/// <summary>
/// Turns whatever a user pasted into a bare host name, and converts between the Unicode and
/// punycode (ACE) forms of an internationalised name.
/// </summary>
internal static class DomainNameNormalizer
{
    private const int MaxDomainLength = 253;
    private const int MaxLabelLength = 63;

    private static readonly IdnMapping Idn = new IdnMapping { AllowUnassigned = true, UseStd3AsciiRules = false };

    private static readonly Regex LabelPattern = new Regex(
        @"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>
    /// Reduces user input to a lower-case host name: strips the scheme, credentials, port, path,
    /// query, fragment, surrounding whitespace and the root dot.
    /// </summary>
    /// <example>
    /// <c>"  HTTPS://user@WWW.Example.COM:8080/path?q=1  "</c> becomes <c>"www.example.com"</c>.
    /// </example>
    public static string Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var text = input!.Trim();

        var scheme = text.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            text = text.Substring(scheme + 3);
        }

        var credentials = text.LastIndexOf('@');
        if (credentials >= 0)
        {
            text = text.Substring(credentials + 1);
        }

        foreach (var separator in new[] { '/', '?', '#' })
        {
            var index = text.IndexOf(separator);
            if (index >= 0)
            {
                text = text.Substring(0, index);
            }
        }

        // A bare colon can only be a port here: IPv6 literals are not domain names.
        var port = text.IndexOf(':');
        if (port >= 0)
        {
            text = text.Substring(0, port);
        }

        return text.Trim().Trim('.').ToLowerInvariant();
    }

    /// <summary>
    /// Converts an internationalised name to its punycode form. ASCII input is returned unchanged,
    /// and a label that cannot be encoded is passed through so validation can reject it.
    /// </summary>
    public static string ToAscii(string domain)
    {
        if (string.IsNullOrEmpty(domain) || IsAscii(domain))
        {
            return domain;
        }

        var labels = domain.Split('.');
        var builder = new StringBuilder(domain.Length + 16);
        for (var i = 0; i < labels.Length; i++)
        {
            if (i > 0)
            {
                builder.Append('.');
            }

            builder.Append(EncodeLabel(labels[i]));
        }

        return builder.ToString();
    }

    /// <summary>Converts punycode labels back to Unicode — the inverse of <see cref="ToAscii"/>.</summary>
    public static string ToUnicode(string domain)
    {
        if (string.IsNullOrEmpty(domain) || domain.IndexOf("xn--", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return domain;
        }

        var labels = domain.Split('.');
        var builder = new StringBuilder(domain.Length);
        for (var i = 0; i < labels.Length; i++)
        {
            if (i > 0)
            {
                builder.Append('.');
            }

            builder.Append(DecodeLabel(labels[i]));
        }

        return builder.ToString();
    }

    /// <summary>Returns true when every label of the ASCII form is a legal DNS label.</summary>
    public static bool IsValidHostName(string? asciiDomain)
    {
        if (string.IsNullOrEmpty(asciiDomain) || asciiDomain!.Length > MaxDomainLength || !IsAscii(asciiDomain))
        {
            return false;
        }

        foreach (var label in asciiDomain.Split('.'))
        {
            if (label.Length == 0 || label.Length > MaxLabelLength || !LabelPattern.IsMatch(label))
            {
                return false;
            }
        }

        return true;
    }

    private static string EncodeLabel(string label)
    {
        if (IsAscii(label))
        {
            return label;
        }

        try
        {
            return Idn.GetAscii(label);
        }
        catch (ArgumentException)
        {
            return label;
        }
    }

    private static string DecodeLabel(string label)
    {
        if (!label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase))
        {
            return label;
        }

        try
        {
            return Idn.GetUnicode(label.ToLowerInvariant());
        }
        catch (ArgumentException)
        {
            return label;
        }
    }

    private static bool IsAscii(string value)
    {
        foreach (var c in value)
        {
            if (c > 127)
            {
                return false;
            }
        }

        return true;
    }
}

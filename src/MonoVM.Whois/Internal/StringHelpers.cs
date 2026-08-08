using System;
using System.Collections.Generic;
using System.Text;

namespace MonoVM.Whois.Internal;

/// <summary>
/// Small string utilities shared across the library.
/// </summary>
/// <remarks>
/// They exist mainly so the code reads the same on every target framework: several of the
/// convenient overloads (<c>string.Contains(string, StringComparison)</c> for one) are missing
/// from netstandard2.0.
/// </remarks>
internal static class StringHelpers
{
    private static readonly char[] NewLineChars = { '\r', '\n' };

    /// <summary>Case-insensitive, culture-independent substring test.</summary>
    public static bool ContainsCi(this string? haystack, string? needle)
    {
        if (string.IsNullOrEmpty(haystack) || string.IsNullOrEmpty(needle))
        {
            return false;
        }

        return haystack!.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>Case-insensitive, culture-independent equality.</summary>
    public static bool EqualsCi(this string? left, string? right)
        => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    /// <summary>Splits text into lines, keeping empty ones.</summary>
    public static string[] SplitLines(this string text)
        => text.Split(NewLineChars, StringSplitOptions.None);

    /// <summary>Truncates <paramref name="text"/> and appends an ellipsis when it was cut.</summary>
    public static string Preview(this string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        return text!.Length <= maxLength ? text : text.Substring(0, maxLength) + "...";
    }

    /// <summary>
    /// Reads a definition flag the way the JSON files write them: <c>"true"</c>, <c>"1"</c>,
    /// <c>"yes"</c> and <c>"on"</c> are all true, anything else is false.
    /// </summary>
    public static bool ToFlag(this string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        switch (value!.Trim().ToLowerInvariant())
        {
            case "1":
            case "true":
            case "yes":
            case "on":
                return true;
            default:
                return false;
        }
    }

    /// <summary>Joins non-empty values with a separator.</summary>
    public static string JoinNonEmpty(string separator, IEnumerable<string?> values)
    {
        var builder = new StringBuilder();
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append(separator);
            }

            builder.Append(value!.Trim());
        }

        return builder.ToString();
    }
}

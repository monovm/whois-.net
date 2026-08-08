using System;
using System.Globalization;
using System.Text.RegularExpressions;

namespace MonoVM.Whois.Parsing;

/// <summary>
/// Reads the many ways a registry can write a date.
/// </summary>
/// <remarks>
/// ICANN mandates ISO 8601 for generic suffixes and most of them comply. The country-code
/// registries were there first and write what they always have: <c>01-Jan-2020</c>,
/// <c>2020.01.01 12:00:00</c>, <c>01/01/2020</c>, sometimes with a trailing note in brackets. A
/// value that cannot be read with confidence is left unparsed rather than guessed at — a wrong
/// expiry date is worse than none.
/// </remarks>
public static class WhoisDateParser
{
    private static readonly string[] ExactFormats =
    {
        "yyyy-MM-ddTHH:mm:ssK",
        "yyyy-MM-dd HH:mm:ssK",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd HH:mm",
        "yyyy-MM-dd",
        "yyyy.MM.dd HH:mm:ss",
        "yyyy.MM.dd",
        "yyyy/MM/dd HH:mm:ss",
        "yyyy/MM/dd",
        "yyyyMMdd",
        "d-MMM-yyyy HH:mm:ss",
        "d-MMM-yyyy",
        "d MMM yyyy HH:mm:ss",
        "d MMM yyyy",

        // Day first, which is what every registry outside North America means by a dotted or
        // slashed date. Single-letter specifiers also accept the zero-padded form.
        "d.M.yyyy HH:mm:ss",
        "d.M.yyyy",
        "d/M/yyyy HH:mm:ss",
        "d/M/yyyy",
        "MMMM d yyyy",
        "d MMMM yyyy",
    };

    private static readonly Regex TrailingNote = new Regex(
        @"\s*[\(\[][^)\]]*[\)\]]\s*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex TrailingZone = new Regex(
        @"\s+(?:utc|gmt|est|edt|cst|cdt|mst|mdt|pst|pdt|cet|cest)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Parses <paramref name="value"/>, or returns <see langword="null"/>.</summary>
    /// <remarks>A value with no offset is read as UTC, which is what registries mean by it.</remarks>
    public static DateTimeOffset? Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = Clean(value!);
        if (text.Length == 0)
        {
            return null;
        }

        const DateTimeStyles Styles = DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal;

        // Exact formats first, deliberately. Left to the general parser, "02.01.2020" is read as
        // 1 February under a month-first culture and 2 January under a day-first one — and the
        // registries that write dates that way all mean day first.
        if (DateTimeOffset.TryParseExact(text, ExactFormats, CultureInfo.InvariantCulture, Styles, out var parsed))
        {
            return Sanity(parsed);
        }

        if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, Styles, out parsed))
        {
            return Sanity(parsed);
        }

        return null;
    }

    private static string Clean(string value)
    {
        var text = value.Trim();

        // "2020-01-01T00:00:00Z (registry local time)" and friends.
        text = TrailingNote.Replace(text, string.Empty);
        text = TrailingZone.Replace(text, string.Empty);

        // Some registries write the offset without a colon or with a stray comma.
        text = text.Trim().TrimEnd(',', ';', '.');

        return text;
    }

    private static DateTimeOffset? Sanity(DateTimeOffset value)
    {
        // Registries do occasionally emit 0000-00-00 or a year in the 1600s. Neither is a date any
        // caller can use, and passing one on invites arithmetic that quietly makes no sense.
        if (value.Year < 1985 || value.Year > 2200)
        {
            return null;
        }

        return value.ToUniversalTime();
    }
}

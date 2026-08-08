using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace MonoVM.Whois.Detection.Patterns;

/// <summary>
/// Shared machinery for the pattern tables: compilation, key/value tolerance and anchoring.
/// </summary>
/// <remarks>
/// Every table in this namespace is built once, at type-initialisation time, and reused for the
/// life of the process. Compiling forty regular expressions per lookup is the kind of cost that
/// only shows up under bulk checks, which is exactly when this library is worked hardest.
/// </remarks>
internal static class PatternCatalog
{
    /// <summary>
    /// What sits between a key and its value.
    /// </summary>
    /// <remarks>
    /// Traficom (.fi) and NIC Monaco pad their keys out with dots —
    /// <c>status.............: Registered</c> — which a plain <c>status:</c> match walks straight
    /// past. A missed "Registered" reads as availability, so the tolerance is not cosmetic.
    /// </remarks>
    public const string Separator = @"[\s._·-]*:[ \t]*";

    private const RegexOptions Options =
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>Compiles one pattern with the library's standard options.</summary>
    public static Regex Compile(string pattern) => new Regex(pattern, Options);

    /// <summary>Compiles a table of patterns.</summary>
    public static Regex[] CompileAll(params string[] patterns)
    {
        var compiled = new Regex[patterns.Length];
        for (var i = 0; i < patterns.Length; i++)
        {
            compiled[i] = Compile(patterns[i]);
        }

        return compiled;
    }

    /// <summary>
    /// Compiles a pattern that must appear at the very start of the reply.
    /// </summary>
    /// <remarks>
    /// Anchoring expresses "this wording opens the reply" without mutating the text being
    /// examined — an alternative would be prepending a sentinel to every response, which corrupts
    /// the first real line for every later consumer of the text.
    /// </remarks>
    public static Regex Anchored(string pattern) => Compile(@"\A[\s\-]*(?:" + pattern + ")");

    /// <summary>
    /// Turns a human-written field label such as <c>"name server:"</c> into a regular expression
    /// that also matches padded keys and tab-aligned values.
    /// </summary>
    public static string Field(string label)
    {
        var parts = label.Split(':');
        var builder = new StringBuilder();

        for (var i = 0; i < parts.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(Separator);
            }

            var part = parts[i].Trim();
            if (part.Length == 0)
            {
                continue;
            }

            // Regex.Escape turns a space into "\ "; either form should tolerate runs of whitespace.
            builder.Append(Regex.Escape(part).Replace(@"\ ", @"\s+").Replace(" ", @"\s+"));
        }

        return builder.ToString();
    }

    /// <summary>Compiles a table of field labels through <see cref="Field"/>.</summary>
    public static Regex[] CompileFields(params string[] labels)
    {
        var compiled = new Regex[labels.Length];
        for (var i = 0; i < labels.Length; i++)
        {
            compiled[i] = Compile(Field(labels[i]));
        }

        return compiled;
    }

    /// <summary>Returns the first pattern in <paramref name="patterns"/> that matches, if any.</summary>
    public static Regex? FirstMatch(IReadOnlyList<Regex> patterns, string text)
    {
        for (var i = 0; i < patterns.Count; i++)
        {
            if (patterns[i].IsMatch(text))
            {
                return patterns[i];
            }
        }

        return null;
    }

    /// <summary>Counts how many of <paramref name="patterns"/> match, stopping at <paramref name="limit"/>.</summary>
    public static int CountMatches(IReadOnlyList<Regex> patterns, string text, int limit = int.MaxValue)
    {
        var found = 0;
        for (var i = 0; i < patterns.Count && found < limit; i++)
        {
            if (patterns[i].IsMatch(text))
            {
                found++;
            }
        }

        return found;
    }

    /// <summary>Builds a lookup of per-suffix pattern tables.</summary>
    public static IReadOnlyDictionary<string, Regex[]> CompileByTld(
        IEnumerable<KeyValuePair<string, string[]>> table)
    {
        var map = new Dictionary<string, Regex[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in table)
        {
            map[entry.Key] = CompileAll(entry.Value);
        }

        return map;
    }
}

using System;
using System.Collections.Generic;
using System.Text;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Detection;

/// <summary>
/// The reply under examination, plus the derived views of it that the rules share.
/// </summary>
/// <remarks>
/// <para>
/// Every rule needs some cheap projection of the same text — lower-cased, or with banner lines
/// stripped, or split into lines. Computing those once per response instead of once per rule keeps
/// a chain of twelve rules to a single pass over the reply, and keeps the rules themselves free of
/// duplicated string plumbing.
/// </para>
/// <para>
/// Instances are immutable and safe to share between rules.
/// </para>
/// </remarks>
public sealed class AvailabilityContext
{
    private static readonly string[] CommentPrefixes = { "%", "#", ";", ">>>", "---", "*" };

    private static readonly string[] BannerFragments =
    {
        "available on web at",
        "find the terms and conditions",
    };

    /// <summary>Builds a context from a transport response.</summary>
    public AvailabilityContext(WhoisResponse response, WhoisServerDefinition? server = null)
        : this(
            (response ?? throw new ArgumentNullException(nameof(response))).Text,
            server?.Tld ?? response.Domain.AsciiTld,
            server,
            response.Protocol,
            response.HttpStatusCode)
    {
        Domain = response.Domain;
    }

    /// <summary>Builds a context from raw text, for tests and for re-analysing a stored reply.</summary>
    public AvailabilityContext(
        string text,
        string? tld = null,
        WhoisServerDefinition? server = null,
        WhoisProtocol protocol = WhoisProtocol.Whois43,
        int? httpStatusCode = null)
    {
        Text = text ?? string.Empty;
        Tld = DomainName.NormalizeSuffix(tld);
        Server = server;
        Protocol = protocol;
        HttpStatusCode = httpStatusCode;

        LowerText = Text.ToLowerInvariant();

        var lines = Text.SplitLines();
        var meaningful = 0;
        var filtered = new StringBuilder(Text.Length);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (IsCommentLine(line))
            {
                continue;
            }

            meaningful++;

            if (IsBannerLine(line))
            {
                continue;
            }

            if (filtered.Length > 0)
            {
                filtered.Append(' ');
            }

            filtered.Append(line);
        }

        MeaningfulLineCount = meaningful;
        FilteredText = filtered.ToString().ToLowerInvariant();
    }

    /// <summary>The domain asked about, when the context came from a real lookup.</summary>
    public DomainName? Domain { get; }

    /// <summary>The suffix, punycode, with a leading dot. Empty when unknown.</summary>
    public string Tld { get; }

    /// <summary>The definition of the server that answered, when known.</summary>
    public WhoisServerDefinition? Server { get; }

    /// <summary>Which protocol produced the reply.</summary>
    public WhoisProtocol Protocol { get; }

    /// <summary>HTTP status of an RDAP reply.</summary>
    public int? HttpStatusCode { get; }

    /// <summary>The reply, verbatim.</summary>
    public string Text { get; }

    /// <summary>The reply, lower-cased.</summary>
    public string LowerText { get; }

    /// <summary>
    /// The reply with blank lines, comment lines and boilerplate banners removed, collapsed onto a
    /// single lower-case line. This is what keyword rules match against, so that a registry's legal
    /// preamble cannot supply the words that decide the verdict.
    /// </summary>
    public string FilteredText { get; }

    /// <summary>How many non-blank, non-comment lines the reply had.</summary>
    public int MeaningfulLineCount { get; }

    /// <summary>True when the reply was nothing but whitespace.</summary>
    public bool IsEmpty => Text.Trim().Length == 0;

    /// <summary>True when the reply looks like an RDAP JSON document.</summary>
    public bool IsRdapDocument => Protocol == WhoisProtocol.Rdap || Text.ContainsCi("\"rdapConformance\"");

    /// <summary>Case-insensitive substring test against the verbatim reply.</summary>
    public bool Contains(string fragment) => Text.ContainsCi(fragment);

    /// <summary>
    /// True when any of <paramref name="fragments"/> appears in the verbatim reply.
    /// Fragments must already be lower-case; the pattern catalogs guarantee that.
    /// </summary>
    public bool ContainsAny(IReadOnlyList<string> fragments)
    {
        for (var i = 0; i < fragments.Count; i++)
        {
            if (LowerText.IndexOf(fragments[i], StringComparison.Ordinal) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when any of <paramref name="fragments"/> appears in the reply once banners and comment
    /// lines have been discarded.
    /// </summary>
    public bool FilteredContainsAny(IReadOnlyList<string> fragments)
    {
        for (var i = 0; i < fragments.Count; i++)
        {
            if (FilteredText.IndexOf(fragments[i], StringComparison.Ordinal) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Returns the first of <paramref name="fragments"/> present in the reply, if any.</summary>
    public string? FirstMatch(IReadOnlyList<string> fragments)
    {
        for (var i = 0; i < fragments.Count; i++)
        {
            if (LowerText.IndexOf(fragments[i], StringComparison.Ordinal) >= 0)
            {
                return fragments[i];
            }
        }

        return null;
    }

    private static bool IsCommentLine(string line)
    {
        foreach (var prefix in CommentPrefixes)
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsBannerLine(string line)
    {
        foreach (var fragment in BannerFragments)
        {
            if (line.ContainsCi(fragment))
            {
                return true;
            }
        }

        return false;
    }
}

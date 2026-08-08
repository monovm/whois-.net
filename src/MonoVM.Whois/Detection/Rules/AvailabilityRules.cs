using System;
using MonoVM.Whois.Detection.Patterns;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Detection.Rules;

/// <summary>
/// Reads an RDAP error document reporting that the object does not exist.
/// </summary>
/// <remarks>
/// RDAP answers an unregistered name with HTTP 404 and a small JSON body carrying
/// <c>"errorCode": 404</c>. That is an unambiguous "no such domain" and deserves to be read as one
/// — unlike a bare <c>404</c> anywhere in the text, which also occurs inside registry domain IDs.
/// </remarks>
public sealed class RdapNotFoundRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "rdap-not-found";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.RdapNotFound;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        if (context.HttpStatusCode == 404)
        {
            return AvailabilityRuleResult.Available("the RDAP service answered 404 Not Found", "HTTP 404");
        }

        if (!context.IsRdapDocument || !context.Text.ContainsCi("\"errorCode\""))
        {
            return AvailabilityRuleResult.Continue;
        }

        return context.Text.ContainsCi("404") || context.Text.ContainsCi("\"title\": \"Not Found\"")
            ? AvailabilityRuleResult.Available("the RDAP document reports the object does not exist", "errorCode 404")
            : AvailabilityRuleResult.Continue;
    }
}

/// <summary>Phrases that mean the name is free, matched with banners and comments stripped out.</summary>
public sealed class AvailabilityKeywordRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "availability-keyword";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.AvailabilityKeyword;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        foreach (var keyword in AvailabilitySignals.Keywords)
        {
            if (context.FilteredText.IndexOf(keyword, StringComparison.Ordinal) >= 0)
            {
                return AvailabilityRuleResult.Available("the reply says the name is not registered", keyword);
            }
        }

        return AvailabilityRuleResult.Continue;
    }
}

/// <summary>The same phrases as patterns, so punctuation and whitespace cannot hide them.</summary>
public sealed class NoMatchPatternRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "no-match-pattern";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.NoMatchPattern;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        var match = PatternCatalog.FirstMatch(AvailabilitySignals.NoMatch, context.Text)
                    ?? PatternCatalog.FirstMatch(AvailabilitySignals.AnchoredNoMatch, context.Text);

        return match is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Available("the reply matches a no-such-domain pattern", match.ToString());
    }
}

/// <summary>Per-suffix wording that means the name is free.</summary>
/// <remarks>
/// The loosest of the tables — several registries answer with nothing more distinctive than the
/// word "available" — so it runs after everything that could show the name is taken.
/// </remarks>
public sealed class TldAvailabilityRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "tld-availability";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.TldAvailability;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        if (context.Tld.Length == 0 || !AvailabilitySignals.ByTld.TryGetValue(context.Tld, out var patterns))
        {
            return AvailabilityRuleResult.Continue;
        }

        var match = PatternCatalog.FirstMatch(patterns, context.Text);
        return match is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Available(
                $"the {context.Tld} registry words availability this way", match.ToString());
    }
}

/// <summary>An explicit status field stating the name is available.</summary>
public sealed class StatusIndicatorRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "status-indicator";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.StatusIndicator;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        // An error or restriction notice can carry the word "available" while the name is very much
        // taken; it vetoes this rule.
        var veto = context.FirstMatch(RegistrationSignals.ErrorOrRestrictionMarkers);
        if (veto is not null)
        {
            return AvailabilityRuleResult.Continue;
        }

        var match = PatternCatalog.FirstMatch(AvailabilitySignals.StatusIndicators, context.Text);
        return match is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Available("a status field states the name is available", match.ToString());
    }
}

/// <summary>
/// For the few registries that answer an unregistered name with nothing but their banner, treats a
/// record-less reply as availability.
/// </summary>
/// <remarks>
/// <para>
/// This is the one inference from absence in the whole chain, and it is opt-in per suffix through
/// <see cref="WhoisServerDefinition.AvailableWhenEmpty"/> — never a global rule. NIC Monaco is the
/// canonical example: no marker, no "not found", just the banner.
/// </para>
/// <para>
/// Even then it only fires last, once refusals, restriction notices and every registration signal
/// have been ruled out by the rules ahead of it.
/// </para>
/// </remarks>
public sealed class RecordlessReplyRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "recordless-reply";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.RecordlessReply;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        if (context.Server is null || !context.Server.AvailableWhenEmpty)
        {
            return AvailabilityRuleResult.Continue;
        }

        if (context.FirstMatch(RegistrationSignals.ErrorOrRestrictionMarkers) is not null)
        {
            return AvailabilityRuleResult.Continue;
        }

        var fields = PatternCatalog.CountMatches(
            RegistrationSignals.RegistrationFields, context.Text, RegistrationSignals.RegistrationFieldThreshold);

        return fields < RegistrationSignals.RegistrationFieldThreshold
            ? AvailabilityRuleResult.Available(
                $"the {context.Tld} registry answers an unregistered name with its banner and nothing else",
                "no registration fields")
            : AvailabilityRuleResult.Continue;
    }
}

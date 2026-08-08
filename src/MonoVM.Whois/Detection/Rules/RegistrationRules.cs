using MonoVM.Whois.Detection.Patterns;
using MonoVM.Whois.Internal;

namespace MonoVM.Whois.Detection.Rules;

/// <summary>Per-suffix wording that means the name is taken.</summary>
/// <remarks>
/// Consulted before the general table because several registries phrase registration in ways that
/// no general pattern would catch — and a missed "registered" reads as availability.
/// </remarks>
public sealed class TldUnavailabilityRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "tld-unavailability";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.TldUnavailability;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        if (context.Tld.Length == 0 || !RegistrationSignals.ByTld.TryGetValue(context.Tld, out var patterns))
        {
            return AvailabilityRuleResult.Continue;
        }

        var match = PatternCatalog.FirstMatch(patterns, context.Text);
        return match is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Registered(
                $"the {context.Tld} registry reports this name as registered", match.ToString());
    }
}

/// <summary>General wording that means the name is taken, whichever registry said it.</summary>
public sealed class GeneralUnavailabilityRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "general-unavailability";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.GeneralUnavailability;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        var match = PatternCatalog.FirstMatch(RegistrationSignals.General, context.Text)
                    ?? PatternCatalog.FirstMatch(RegistrationSignals.AnchoredGeneral, context.Text);

        return match is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Registered("the reply states the name is registered", match.ToString());
    }
}

/// <summary>
/// Recognises a reply that is shaped like a registration record, whether it is WHOIS text or an
/// RDAP document.
/// </summary>
/// <remarks>
/// Three recognised keys is the threshold. One or two can appear in a banner or an error notice;
/// three together only happen in a record.
/// </remarks>
public sealed class RegistrationRecordRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "registration-record";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.RegistrationRecord;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        if (IsRdapRecord(context))
        {
            return AvailabilityRuleResult.Registered(
                "the RDAP document describes an existing registration", "rdapConformance");
        }

        // .ir publishes almost nothing else, so the pair is the record.
        if (context.Tld == ".ir" && context.Contains("domain:") && context.Contains("nserver:"))
        {
            return AvailabilityRuleResult.Registered("the .ir record names the domain and its name servers", "domain: + nserver:");
        }

        // DENIC says "Status: connect" where other registries say "registered".
        if (context.Tld == ".de" && context.Contains("status: connect"))
        {
            return AvailabilityRuleResult.Registered("DENIC reports the domain as connected", "status: connect");
        }

        var found = PatternCatalog.CountMatches(
            RegistrationSignals.RecordIndicators, context.Text, RegistrationSignals.RecordIndicatorThreshold);

        return found >= RegistrationSignals.RecordIndicatorThreshold
            ? AvailabilityRuleResult.Registered(
                $"the reply carries {found} or more registration fields", "record indicators")
            : AvailabilityRuleResult.Continue;
    }

    private static bool IsRdapRecord(AvailabilityContext context)
    {
        if (!context.Text.ContainsCi("\"rdapConformance\""))
        {
            return false;
        }

        // An RDAP error document — a 404 for a name that does not exist — is not a record.
        if (context.Text.ContainsCi("\"errorCode\""))
        {
            return false;
        }

        var found = 0;
        foreach (var key in RegistrationSignals.RdapRecordKeys)
        {
            if (context.LowerText.IndexOf(key, System.StringComparison.Ordinal) >= 0)
            {
                found++;
            }
        }

        return found >= RegistrationSignals.RdapRecordKeyThreshold;
    }
}

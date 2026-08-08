using MonoVM.Whois.Internal;

namespace MonoVM.Whois.Detection.Rules;

/// <summary>
/// Trusts the marker recorded against the suffix in the server definitions.
/// </summary>
/// <remarks>
/// This is the highest-confidence signal there is: someone looked at what this particular registry
/// prints for an unregistered name and wrote it down. It runs first for that reason.
/// </remarks>
public sealed class RegistryAvailableMarkerRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "registry-available-marker";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.RegistryMarker;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        var marker = context.Server?.AvailableMatch;

        // A naive substring test treats an empty marker as present in every reply, which would
        // call every domain available. An empty marker must match nothing.
        if (string.IsNullOrEmpty(marker))
        {
            return AvailabilityRuleResult.Continue;
        }

        return context.Text.ContainsCi(marker)
            ? AvailabilityRuleResult.Available($"the registry's marker for {context.Tld} is present", marker)
            : AvailabilityRuleResult.Continue;
    }
}

/// <summary>
/// Recognises the marker some registries print for a premium or reserved name.
/// </summary>
/// <remarks>
/// <para>
/// A premium name is <em>not</em> available: the registry is holding it back, and the record is
/// withheld along with it. It is worth distinguishing from an ordinary registration, because the
/// name can usually still be bought — at a price.
/// </para>
/// <para>
/// Runs second, right after the availability marker. Several registries word a premium name as a
/// reservation notice, which the general "registered" patterns match too; the marker recorded
/// against this specific suffix is the more precise of the two and should win.
/// </para>
/// </remarks>
public sealed class RegistryPremiumMarkerRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "registry-premium-marker";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.PremiumMarker;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        var marker = context.Server?.PremiumMatch;
        if (string.IsNullOrEmpty(marker))
        {
            return AvailabilityRuleResult.Continue;
        }

        return context.Text.ContainsCi(marker)
            ? AvailabilityRuleResult.Premium($"the registry flags {context.Tld} names of this kind as premium or reserved", marker)
            : AvailabilityRuleResult.Continue;
    }
}

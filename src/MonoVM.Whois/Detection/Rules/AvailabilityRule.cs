using MonoVM.Whois.Abstractions;

namespace MonoVM.Whois.Detection.Rules;

/// <summary>Convenience base for a detection rule.</summary>
public abstract class AvailabilityRule : IAvailabilityRule
{
    /// <inheritdoc />
    public abstract string Name { get; }

    /// <inheritdoc />
    public abstract int Order { get; }

    /// <inheritdoc />
    public abstract AvailabilityRuleResult Evaluate(AvailabilityContext context);

    /// <inheritdoc />
    public override string ToString() => $"{Order:D4} {Name}";
}

/// <summary>
/// The positions of the built-in rules in the chain.
/// </summary>
/// <remarks>
/// <para>
/// The ordering is the argument. Refusals are recognised before anything is read as a verdict;
/// evidence of registration is weighed before evidence of availability; and the specific beats the
/// general. A rule inserted between two of these constants slots in without touching either.
/// </para>
/// </remarks>
public static class AvailabilityRuleOrder
{
    /// <summary>The registry's own "this name is free" marker, from the server definition.</summary>
    public const int RegistryMarker = 100;

    /// <summary>
    /// The registry's own "this name is premium or reserved" marker, from the server definition.
    /// </summary>
    /// <remarks>
    /// Runs alongside its sibling and ahead of the general patterns for the same reason: someone
    /// looked at what this particular registry prints and wrote it down, which beats a pattern
    /// guessing from the wording. Several registries phrase a premium name as a reservation notice,
    /// and the general "registered" patterns would otherwise claim it first and lose the detail.
    /// </remarks>
    public const int PremiumMarker = 110;

    /// <summary>The server saying it cannot serve this suffix, or is too busy to try.</summary>
    public const int ServerRefusal = 200;

    /// <summary>An RDAP error document reporting that the object does not exist.</summary>
    public const int RdapNotFound = 260;

    /// <summary>Per-suffix wording that means the name is taken.</summary>
    public const int TldUnavailability = 300;

    /// <summary>General wording that means the name is taken.</summary>
    public const int GeneralUnavailability = 310;

    /// <summary>The reply is shaped like a registration record.</summary>
    public const int RegistrationRecord = 320;

    /// <summary>Phrases that mean the name is free.</summary>
    public const int AvailabilityKeyword = 400;

    /// <summary>Patterns that mean the name is free.</summary>
    public const int NoMatchPattern = 410;

    /// <summary>Per-suffix wording that means the name is free.</summary>
    public const int TldAvailability = 420;

    /// <summary>An explicit status field stating the name is free.</summary>
    public const int StatusIndicator = 430;

    /// <summary>A refusal recognised only after every positive signal has been ruled out.</summary>
    public const int NoVerdict = 950;

    /// <summary>A record-less reply, for the few registries where that means the name is free.</summary>
    public const int RecordlessReply = 960;

    /// <summary>An empty reply, which is never a verdict.</summary>
    public const int EmptyReply = 970;
}

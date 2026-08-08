using MonoVM.Whois.Detection;

namespace MonoVM.Whois.Abstractions;

/// <summary>
/// One test applied to a reply on the way to a verdict.
/// </summary>
/// <remarks>
/// <para>
/// Rules form a chain of responsibility ordered by <see cref="Order"/>: each is offered the reply
/// and either answers it or passes. The first conclusive answer wins, so the ordering encodes the
/// priority — refusals before verdicts, "registered" before "free", specific before general.
/// </para>
/// <para>
/// Registering a new rule is the supported way to teach the library about a registry that words
/// things its own way. Nothing else has to change.
/// </para>
/// </remarks>
public interface IAvailabilityRule
{
    /// <summary>A short, stable name; it appears in the verdict's trace.</summary>
    string Name { get; }

    /// <summary>Where this rule sits in the chain. Lower runs first.</summary>
    int Order { get; }

    /// <summary>Examines the reply, and either concludes or passes.</summary>
    AvailabilityRuleResult Evaluate(AvailabilityContext context);
}

/// <summary>Runs the rule chain and reports what it concluded.</summary>
public interface IAvailabilityAnalyzer
{
    /// <summary>Draws a verdict from a reply.</summary>
    AvailabilityVerdict Analyze(AvailabilityContext context);
}

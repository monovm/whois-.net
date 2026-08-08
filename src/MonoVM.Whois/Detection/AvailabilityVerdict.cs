using System;
using System.Collections.Generic;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Detection;

/// <summary>One rule's contribution to a verdict, kept for diagnostics.</summary>
public sealed class AvailabilityRuleTrace
{
    /// <summary>Creates a trace entry.</summary>
    public AvailabilityRuleTrace(string rule, AvailabilityRuleResult result)
    {
        Rule = rule;
        Decision = result.Decision;
        Reason = result.Reason;
        Evidence = result.Evidence;
    }

    /// <summary>Name of the rule.</summary>
    public string Rule { get; }

    /// <summary>What it concluded.</summary>
    public AvailabilityDecision Decision { get; }

    /// <summary>Why.</summary>
    public string? Reason { get; }

    /// <summary>The matched pattern or text fragment.</summary>
    public string? Evidence { get; }

    /// <inheritdoc />
    public override string ToString()
        => Reason is null ? $"{Rule} -> {Decision}" : $"{Rule} -> {Decision} ({Reason})";
}

/// <summary>
/// The conclusion drawn from a reply, together with the reasoning that produced it.
/// </summary>
/// <remarks>
/// The trace is what makes a wrong answer debuggable: it records which rule fired, on what
/// evidence, and — when <see cref="Configuration.WhoisOptions.CollectFullTrace"/> is on — every
/// rule that was consulted along the way.
/// </remarks>
public sealed class AvailabilityVerdict
{
    /// <summary>Creates a verdict.</summary>
    public AvailabilityVerdict(
        DomainAvailabilityStatus status,
        string reason,
        string? decidedBy = null,
        string? evidence = null,
        IReadOnlyList<AvailabilityRuleTrace>? trace = null)
    {
        Status = status;
        Reason = reason;
        DecidedBy = decidedBy;
        Evidence = evidence;
        Trace = trace ?? Array.Empty<AvailabilityRuleTrace>();
    }

    /// <summary>The verdict.</summary>
    public DomainAvailabilityStatus Status { get; }

    /// <summary>Why, in a sentence.</summary>
    public string Reason { get; }

    /// <summary>Which rule decided it.</summary>
    public string? DecidedBy { get; }

    /// <summary>The pattern or text fragment that clinched it.</summary>
    public string? Evidence { get; }

    /// <summary>Every rule consulted, in order.</summary>
    public IReadOnlyList<AvailabilityRuleTrace> Trace { get; }

    /// <summary>True when the registry says the name is free to register.</summary>
    public bool IsAvailable => Status == DomainAvailabilityStatus.Available;

    /// <inheritdoc />
    public override string ToString()
        => DecidedBy is null ? $"{Status}: {Reason}" : $"{Status}: {Reason} [{DecidedBy}]";
}

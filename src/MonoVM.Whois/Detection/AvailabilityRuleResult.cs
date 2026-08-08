namespace MonoVM.Whois.Detection;

/// <summary>The outcome of evaluating one detection rule, with the evidence that produced it.</summary>
public readonly struct AvailabilityRuleResult
{
    private AvailabilityRuleResult(AvailabilityDecision decision, string? reason, string? evidence)
    {
        Decision = decision;
        Reason = reason;
        Evidence = evidence;
    }

    /// <summary>The rule had nothing to say.</summary>
    public static readonly AvailabilityRuleResult Continue =
        new AvailabilityRuleResult(AvailabilityDecision.Continue, null, null);

    /// <summary>What the rule concluded.</summary>
    public AvailabilityDecision Decision { get; }

    /// <summary>Why, in a sentence a human can read.</summary>
    public string? Reason { get; }

    /// <summary>The pattern or fragment of the reply that triggered the rule.</summary>
    public string? Evidence { get; }

    /// <summary>True when the rule reached a conclusion and the chain should stop.</summary>
    public bool IsConclusive => Decision != AvailabilityDecision.Continue;

    /// <summary>The registry says the name is not registered.</summary>
    public static AvailabilityRuleResult Available(string reason, string? evidence = null)
        => new AvailabilityRuleResult(AvailabilityDecision.Available, reason, evidence);

    /// <summary>The name is registered.</summary>
    public static AvailabilityRuleResult Registered(string reason, string? evidence = null)
        => new AvailabilityRuleResult(AvailabilityDecision.Registered, reason, evidence);

    /// <summary>The name is premium or reserved.</summary>
    public static AvailabilityRuleResult Premium(string reason, string? evidence = null)
        => new AvailabilityRuleResult(AvailabilityDecision.Premium, reason, evidence);

    /// <summary>The server declined to answer.</summary>
    public static AvailabilityRuleResult Refused(string reason, string? evidence = null)
        => new AvailabilityRuleResult(AvailabilityDecision.Refused, reason, evidence);

    /// <summary>The server does not serve this suffix.</summary>
    public static AvailabilityRuleResult Unsupported(string reason, string? evidence = null)
        => new AvailabilityRuleResult(AvailabilityDecision.Unsupported, reason, evidence);

    /// <inheritdoc />
    public override string ToString()
        => Reason is null ? Decision.ToString() : $"{Decision}: {Reason}";
}

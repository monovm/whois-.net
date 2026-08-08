using MonoVM.Whois.Detection.Patterns;

namespace MonoVM.Whois.Detection.Rules;

/// <summary>
/// Recognises a server that did not answer the question: it does not serve this suffix, or it is
/// busy, or it is rate-limiting the client.
/// </summary>
/// <remarks>
/// Runs before every verdict rule. A reply of this shape has no registration fields and no "not
/// found" wording, so anything downstream that reasons from the absence of a record would call it
/// available — and report every registered domain behind a rate limiter as free.
/// </remarks>
public sealed class ServerRefusalRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "server-refusal";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.ServerRefusal;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        var transient = context.FirstMatch(RefusalSignals.TransientFragments);
        if (transient is not null)
        {
            return AvailabilityRuleResult.Refused(
                "the server is busy or rate-limiting; the reply carries no verdict", transient);
        }

        var unsupported = context.FirstMatch(RefusalSignals.UnsupportedFragments);
        if (unsupported is not null)
        {
            return AvailabilityRuleResult.Unsupported(
                "the server that answered does not serve this suffix", unsupported);
        }

        var pattern = PatternCatalog.FirstMatch(RefusalSignals.UnsupportedPatterns, context.Text);
        return pattern is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Unsupported(
                "the server that answered does not serve this suffix", pattern.ToString());
    }
}

/// <summary>
/// The last word on a reply nothing else recognised: if it looks like a refusal, say so instead of
/// guessing.
/// </summary>
/// <remarks>
/// Reached only after every positive signal has been ruled out, so a real record or a real
/// "not found" is never affected. Covers rate limiting, blocked clients, and registries that have
/// retired port 43 in favour of RDAP.
/// </remarks>
public sealed class NoVerdictRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "no-verdict";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.NoVerdict;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
    {
        var pattern = PatternCatalog.FirstMatch(RefusalSignals.NoVerdictPatterns, context.Text);
        return pattern is null
            ? AvailabilityRuleResult.Continue
            : AvailabilityRuleResult.Refused(
                "the server declined the query — rate limited, blocked, or port 43 retired in favour of RDAP",
                pattern.ToString());
    }
}

/// <summary>An empty reply is not evidence of anything.</summary>
/// <remarks>
/// Runs after <see cref="RecordlessReplyRule"/>, which is the one place an absent record is allowed
/// to mean "free" — and only for the registries that documented it.
/// </remarks>
public sealed class EmptyReplyRule : AvailabilityRule
{
    /// <inheritdoc />
    public override string Name => "empty-reply";

    /// <inheritdoc />
    public override int Order => AvailabilityRuleOrder.EmptyReply;

    /// <inheritdoc />
    public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
        => context.IsEmpty
            ? AvailabilityRuleResult.Refused("the server answered with nothing at all")
            : AvailabilityRuleResult.Continue;
}

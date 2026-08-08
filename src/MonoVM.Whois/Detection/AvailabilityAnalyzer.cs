using System;
using System.Collections.Generic;
using System.Linq;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Detection.Rules;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Detection;

/// <summary>
/// Runs the rule chain over a reply and reports the first conclusion reached.
/// </summary>
/// <remarks>
/// <para>
/// The analyzer owns no patterns and knows no registries. It orders the rules, offers each of them
/// the reply, stops at the first conclusive answer, and records how it got there. Everything that
/// could need changing when a registry changes its wording lives in a rule, not here.
/// </para>
/// <para>
/// Thread-safe and stateless: one instance can serve any number of concurrent lookups.
/// </para>
/// </remarks>
public sealed class AvailabilityAnalyzer : IAvailabilityAnalyzer
{
    private readonly IAvailabilityRule[] _rules;
    private readonly bool _collectFullTrace;

    /// <summary>Creates an analyzer over <paramref name="rules"/>, or over the built-in set.</summary>
    /// <param name="rules">The chain to run. Ordered by <see cref="IAvailabilityRule.Order"/>.</param>
    /// <param name="options">Supplies <see cref="WhoisOptions.CollectFullTrace"/>.</param>
    public AvailabilityAnalyzer(IEnumerable<IAvailabilityRule>? rules = null, WhoisOptions? options = null)
    {
        _rules = (rules ?? CreateDefaultRules())
            .Where(rule => rule is not null)
            .OrderBy(rule => rule.Order)
            .ThenBy(rule => rule.Name, StringComparer.Ordinal)
            .ToArray();

        if (_rules.Length == 0)
        {
            throw new ArgumentException("An analyzer needs at least one rule.", nameof(rules));
        }

        _collectFullTrace = options?.CollectFullTrace ?? false;
    }

    /// <summary>An analyzer with the built-in rules and default options.</summary>
    public static AvailabilityAnalyzer Default { get; } = new AvailabilityAnalyzer();

    /// <summary>The chain this analyzer runs, in order.</summary>
    public IReadOnlyList<IAvailabilityRule> Rules => _rules;

    /// <summary>
    /// The rules shipped with the library.
    /// </summary>
    /// <remarks>
    /// Returned as a fresh list so callers can add, remove or replace entries and hand the result
    /// back to the constructor — the supported way to teach the library a registry's local dialect.
    /// </remarks>
    public static IList<IAvailabilityRule> CreateDefaultRules() => new List<IAvailabilityRule>
    {
        new RegistryAvailableMarkerRule(),
        new RegistryPremiumMarkerRule(),
        new ServerRefusalRule(),
        new RdapNotFoundRule(),
        new TldUnavailabilityRule(),
        new GeneralUnavailabilityRule(),
        new RegistrationRecordRule(),
        new AvailabilityKeywordRule(),
        new NoMatchPatternRule(),
        new TldAvailabilityRule(),
        new StatusIndicatorRule(),
        new NoVerdictRule(),
        new RecordlessReplyRule(),
        new EmptyReplyRule(),
    };

    /// <inheritdoc />
    public AvailabilityVerdict Analyze(AvailabilityContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        List<AvailabilityRuleTrace>? trace = _collectFullTrace ? new List<AvailabilityRuleTrace>(_rules.Length) : null;

        foreach (var rule in _rules)
        {
            var result = rule.Evaluate(context);

            trace?.Add(new AvailabilityRuleTrace(rule.Name, result));

            if (!result.IsConclusive)
            {
                continue;
            }

            var decided = trace ?? new List<AvailabilityRuleTrace> { new AvailabilityRuleTrace(rule.Name, result) };

            return new AvailabilityVerdict(
                ToStatus(result.Decision),
                result.Reason ?? rule.Name,
                rule.Name,
                result.Evidence,
                decided);
        }

        // Nothing recognised the reply. Defaulting to "registered" is the deliberate choice: the
        // opposite default would turn every unrecognised reply into a domain reported as free.
        return new AvailabilityVerdict(
            DomainAvailabilityStatus.Registered,
            "no availability signal was recognised in the reply",
            decidedBy: null,
            evidence: null,
            trace: trace);
    }

    private static DomainAvailabilityStatus ToStatus(AvailabilityDecision decision) => decision switch
    {
        AvailabilityDecision.Available => DomainAvailabilityStatus.Available,
        AvailabilityDecision.Registered => DomainAvailabilityStatus.Registered,
        AvailabilityDecision.Premium => DomainAvailabilityStatus.Premium,
        AvailabilityDecision.Refused => DomainAvailabilityStatus.Error,
        AvailabilityDecision.Unsupported => DomainAvailabilityStatus.Error,
        _ => DomainAvailabilityStatus.Unknown,
    };
}

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MonoVM.Whois.Detection.Patterns;

/// <summary>
/// Everything that says "this name is free": the phrases registries use, in the several languages
/// they use them in, plus the per-suffix variants that no general pattern would catch.
/// </summary>
/// <remarks>
/// Availability is only ever concluded from a positive signal. There is no rule here that infers
/// freedom from a reply being short, empty or unrecognised — every one of those shapes is also
/// what a rate-limited or blocked server returns for a registered name.
/// </remarks>
internal static class AvailabilitySignals
{
    /// <summary>
    /// Phrases matched against the reply with banners and comment lines stripped out, so that a
    /// registry's legal preamble cannot supply the words that decide the verdict.
    /// </summary>
    /// <remarks>
    /// The bare word "free" is deliberately absent: it turns any registrar footer offering a free
    /// service into a false "available".
    /// </remarks>
    public static readonly string[] Keywords =
    {
        "no match",
        "not found",
        "no data found",
        "no entries found",
        "available for registration",
        "domain status: available",
        "no matching record",
        "not registered",
        "no object found",
        "no such domain",
        "no such object",
        "object does not exist",
        "nothing found",
        "no domain",
        "domain not found",
        "status: available",
        "registration status: available",
        "status: free",
        "is free",
        "domain name not known",
        "domain has not been registered",
        "domain name has not been registered",
        "has not been registered",
        "is available for purchase",
        "is available for registration",
        "no se encontro el objeto",
        "no se encontró el objeto",
        "object_not_found",
        "el dominio no se encuentra registrado",
        "domain is available",
        "domain does not exist",
        "does not exist in database",
        "was not found",
        "not exist",
        "no está registrado",
        "no esta registrado",
        "not found...",
        "no information available about domain name",
    };

    /// <summary>
    /// The same idea as <see cref="Keywords"/>, expressed as patterns so that whitespace, tabs and
    /// punctuation between the words cannot hide the phrase.
    /// </summary>
    public static readonly Regex[] NoMatch = PatternCatalog.CompileAll(
        @"no\s+match",
        @"not\s+found",
        @"no\s+data\s+found",
        @"no\s+entries\s+found",
        @"no\s+matching\s+record",
        @"object\s+does\s+not\s+exist",
        @"no\s+such\s+domain",
        @"domain\s+not\s+found",
        "status" + PatternCatalog.Separator + "available",
        @"registration\s+status" + PatternCatalog.Separator + "available",
        "status" + PatternCatalog.Separator + "free",
        @"\bis\s+free\b",
        @"domain\s+name\s+not\s+known",
        @"domain\s+has\s+not\s+been\s+registered",
        @"domain\s+name\s+has\s+not\s+been\s+registered",
        @"\bis\s+available\s+for",
        @"no\s+se\s+encontro\s+el\s+objeto",
        @"object_not_found",
        @"el\s+dominio\s+no\s+se\s+encuentra\s+registrado",
        @"domain\s+is\s+available",
        @"domain\s+does\s+not\s+exist",
        @"does\s+not\s+exist\s+in\s+database",
        @"was\s+not\s+found",
        @"not\s+exist",
        @"no\s+est[áa]\s+registrado",
        @"%error\s*:\s*103");

    /// <summary>Phrases that only mean availability when the reply opens with them.</summary>
    public static readonly Regex[] AnchoredNoMatch =
    {
        PatternCatalog.Anchored(@"available"),
        PatternCatalog.Anchored(@"not\s+found"),
        PatternCatalog.Anchored(@"domain\s+not\s+found"),
    };

    /// <summary>An explicit status field stating the name is available.</summary>
    public static readonly Regex[] StatusIndicators = PatternCatalog.CompileAll(
        "status" + PatternCatalog.Separator + "available",
        "status" + PatternCatalog.Separator + "free",
        @"registration\s+status" + PatternCatalog.Separator + "available",
        @"domain\s+status" + PatternCatalog.Separator + "available",
        @"availability" + PatternCatalog.Separator + "available",
        @"state" + PatternCatalog.Separator + "available",
        @"status\s*=\s*available");

    /// <summary>
    /// Per-suffix wording, consulted after the general patterns because it is the loosest of the
    /// tables: several registries answer with nothing more distinctive than the word "available".
    /// </summary>
    public static readonly IReadOnlyDictionary<string, Regex[]> ByTld = BuildByTld();

    private static Dictionary<string, Regex[]> BuildByTld()
    {
        var table = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            // Major suffixes
            [".com"] = new[] { @"no\s+match\s+for", @"domain\s+not\s+found" },
            [".net"] = new[] { @"no\s+match\s+for", @"domain\s+not\s+found" },
            [".org"] = new[] { @"domain\s+not\s+found", @"not\s+found" },
            [".uk"] = new[] { @"no\s+match", @"this\s+domain\s+is\s+available", @"has\s+not\s+been\s+registered" },
            [".de"] = new[] { @"is\s+available\s+for\s+registration", "status" + PatternCatalog.Separator + "free" },
            [".fr"] = new[] { @"not\s+found", @"available" },
            [".it"] = new[] { @"\bavailable\b", "status" + PatternCatalog.Separator + "available" },
            [".au"] = new[] { @"is\s+available\s+for\s+registration" },
            [".com.au"] = new[] { @"is\s+available\s+for\s+registration" },
            [".org.au"] = new[] { @"is\s+available\s+for\s+registration" },
            [".net.au"] = new[] { @"is\s+available\s+for\s+registration" },
            [".be"] = new[] { "status" + PatternCatalog.Separator + "available", @"\bfree\b" },
            [".ca"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ch"] = new[] { @"we\s+do\s+not\s+have\s+an\s+entry", @"\bavailable\b" },
            [".li"] = new[] { @"we\s+do\s+not\s+have\s+an\s+entry", @"\bavailable\b" },
            [".eu"] = new[] { "status" + PatternCatalog.Separator + "available", @"\bavailable\b" },
            [".nl"] = new[] { @"\bis\s+free\b", @"\bavailable\b" },
            [".dk"] = new[] { @"\bavailable\b" },
            [".no"] = new[] { @"\bavailable\b" },
            [".se"] = new[] { @"\bavailable\b" },
            [".fi"] = new[] { @"\bavailable\b" },
            [".pt"] = new[] { @"\bavailable\b" },
            [".es"] = new[] { @"\bavailable\b" },

            // Asia-Pacific
            [".jp"] = new[] { @"no\s+match!!", @"no\s+match" },
            [".cn"] = new[] { @"no\s+matching\s+record", @"not\s+found" },
            [".in"] = new[] { @"not\s+found", @"no\s+data\s+found" },
            [".hk"] = new[] { @"the\s+domain\s+has\s+not\s+been\s+registered" },
            [".tw"] = new[] { @"no\s+found", @"not\s+found" },
            [".sg"] = new[] { @"domain\s+not\s+found" },
            [".my"] = new[] { @"does\s+not\s+exist\s+in\s+database" },
            [".ph"] = new[] { @"domain\s+is\s+available" },
            [".th"] = new[] { @"no\s+match\s+found" },
            [".vn"] = new[] { @"\bavailable\b", @"not\s+found" },
            [".id"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },

            // Americas
            [".us"] = new[] { @"not\s+found", @"domain\s+not\s+found" },
            [".mx"] = new[] { @"no_se_encontro_el_objeto", @"not\s+found" },
            [".br"] = new[] { @"no\s+match\s+for", @"domain\s+not\s+found" },
            [".ar"] = new[] { @"el\s+dominio\s+no\s+se\s+encuentra\s+registrado" },
            [".co"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".cl"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".pe"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ve"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".ec"] = new[] { @"\bavailable\b" },

            // Europe
            [".ru"] = new[] { @"no\s+entries\s+found", @"not\s+found" },
            [".pl"] = new[] { @"no\s+information\s+available", @"\bavailable\b" },
            [".cz"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".sk"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".hu"] = new[] { @"no\s+match", @"\bavailable\b" },
            [".ro"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".rs"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".me"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ba"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".mk"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".al"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".md"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".ua"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".gr"] = new[] { @"not\s+exist" },
            [".ir"] = new[] { @"no\s+entries\s+found" },

            // Africa
            [".za"] = new[] { @"\bavailable\b", @"not\s+found" },
            [".co.za"] = new[] { @"\bavailable\b", @"not\s+found" },
            [".ng"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ke"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".ma"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".tn"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".eg"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ci"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".sn"] = new[] { @"not\s+found", @"\bavailable\b" },

            // Oceania
            [".nz"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ws"] = new[] { @"the\s+queried\s+object\s+does\s+not\s+exist" },
            [".cc"] = new[] { @"no\s+match", @"\bavailable\b" },
            [".to"] = new[] { @"no\s+match\s+for", @"\bavailable\b" },

            // Islands and small registries
            [".im"] = new[] { @"was\s+not\s+found", @"\bavailable\b" },
            [".io"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".sh"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".ac"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".gg"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".je"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".as"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".ms"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".tc"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".vg"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".gs"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".fm"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".nr"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".pw"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".tk"] = new[] { @"domain\s+name\s+not\s+known", @"\bavailable\b" },
            [".ml"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".ga"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".cf"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".gq"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".cm"] = new[] { @"not\s+registered", @"\bavailable\b" },
            [".bi"] = new[] { @"domain\s+not\s+found", @"\bavailable\b" },
            [".ne"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".cd"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".dj"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".km"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".mg"] = new[] { @"no\s+object\s+found", @"\bavailable\b" },
            [".rw"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".sc"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".so"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".st"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".tz"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".ug"] = new[] { @"no\s+entries\s+found", @"\bavailable\b" },
            [".zm"] = new[] { @"not\s+found", @"\bavailable\b" },
            [".zw"] = new[] { @"no\s+information\s+available", @"\bavailable\b" },
        };

        var compiled = new Dictionary<string, Regex[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in table)
        {
            compiled[entry.Key] = PatternCatalog.CompileAll(entry.Value);
        }

        return compiled;
    }
}

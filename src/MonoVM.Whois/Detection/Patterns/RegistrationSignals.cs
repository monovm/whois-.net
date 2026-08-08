using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MonoVM.Whois.Detection.Patterns;

/// <summary>
/// Everything that says "this name is taken": explicit status wording, the shape of a real record,
/// and the registry notices that withhold a record without releasing the name.
/// </summary>
internal static class RegistrationSignals
{
    private const string StatusRegistered = "status" + PatternCatalog.Separator + "registered";
    private const string StatusActive = "status" + PatternCatalog.Separator + "active";

    /// <summary>
    /// Wording that means "registered" regardless of which registry produced it.
    /// </summary>
    public static readonly Regex[] General = PatternCatalog.CompileAll(
        @"not\s+available",
        @"domain\s+not\s+available",
        "status" + PatternCatalog.Separator + @"not\s+available",
        "registration\\s+status" + PatternCatalog.Separator + @"not\s+available",
        "domain\\s+status" + PatternCatalog.Separator + @"not\s+available",
        "status" + PatternCatalog.Separator + "unavailable",
        StatusRegistered,
        StatusActive,
        "status" + PatternCatalog.Separator + "connect",
        "status" + PatternCatalog.Separator + "client",
        "status" + PatternCatalog.Separator + @"redemption\s*period",
        "status" + PatternCatalog.Separator + "redemption",
        "status" + PatternCatalog.Separator + @"pending\s*delete",
        "status" + PatternCatalog.Separator + @"server\s*hold",
        @"this\s+domain\s+has\s+been\s+registered",
        @"domain\s+registered",
        @"already\s+registered",
        @"currently\s+registered",
        @"\bis\s+registered\b",
        "registration" + PatternCatalog.Separator + "registered",

        // Registry restriction and reservation notices. The name exists, the registry simply
        // withholds the details — CIRA-backed .sx answers "Error code: 01044 … usage restrictions
        // applied" for reserved and premium names. None of these mean the name is free.
        @"usage\s+restrictions",
        @"name\s+is\s+reserved",
        @"reserved\s+domain",
        @"domain\s+is\s+reserved");

    /// <summary>Wording that only means "registered" at the very start of a reply.</summary>
    public static readonly Regex[] AnchoredGeneral =
    {
        PatternCatalog.Anchored(@"not\s+available"),
        PatternCatalog.Anchored(@"not\s+found\b.*\bregistered"),
    };

    /// <summary>
    /// Per-suffix wording, consulted before <see cref="General"/> because some registries phrase
    /// registration in ways that would otherwise slip past.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, Regex[]> ByTld = BuildByTld();

    /// <summary>
    /// Keys that only appear in a real record. Three of them present is taken as proof the reply
    /// describes a registration.
    /// </summary>
    public static readonly Regex[] RecordIndicators = PatternCatalog.CompileFields(
        "domain:",
        "domain name:",
        "ascii:",
        "nserver:",
        "nameserver:",
        "name server:",
        "registrar:",
        "registrant:",
        "creation date:",
        "created:",
        "changed:",
        "expiry date:",
        "expires:",
        "updated:",
        "last updated:",
        "admin contact:",
        "technical contact:",
        "billing contact:",
        "registry domain id:",
        "registrar whois server:",
        "domain status: client",
        "dnssec:");

    /// <summary>How many <see cref="RecordIndicators"/> must be present before a reply counts as a record.</summary>
    public const int RecordIndicatorThreshold = 3;

    /// <summary>
    /// The subset of keys that carry actual registration data, used to decide whether a reply is
    /// record-less for the few registries where that means "free".
    /// </summary>
    public static readonly Regex[] RegistrationFields = PatternCatalog.CompileFields(
        "registrar:",
        "creation date:",
        "created:",
        "expiry date:",
        "expires:",
        "name server:",
        "nameserver:",
        "nserver:",
        "registrant:",
        "admin contact:",
        "technical contact:");

    /// <summary>Below this many registration fields, a reply carries no record.</summary>
    public const int RegistrationFieldThreshold = 2;

    /// <summary>
    /// Markers of an error or restriction notice.
    /// </summary>
    /// <remarks>
    /// Absence of registration fields is not proof of availability: these notices have no fields
    /// either, yet the domain behind them is registered. Their presence vetoes any inference drawn
    /// from a reply being short or record-less.
    /// </remarks>
    public static readonly string[] ErrorOrRestrictionMarkers =
    {
        "error code:",
        "error message:",
        "usage restrictions",
        "please see your registrar",
        "please contact",
        "is reserved",
        "reserved name",
        "restricted",
        "denied",
        "access denied",
        "not authorized",
        "unauthorized",
    };

    /// <summary>JSON keys that only an RDAP record for an existing domain carries.</summary>
    public static readonly string[] RdapRecordKeys =
    {
        "\"ldhname\"",
        "\"nameservers\"",
        "\"securedns\"",
        "\"objectclassname\"",
        "\"events\"",
        "\"entities\"",
    };

    /// <summary>How many <see cref="RdapRecordKeys"/> mark an RDAP reply as describing a registration.</summary>
    public const int RdapRecordKeyThreshold = 2;

    private static Dictionary<string, Regex[]> BuildByTld()
    {
        var table = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [".com.au"] = new[] { @"not\s+available", @"domain\s+not\s+available" },
            [".au"] = new[] { @"not\s+available", @"domain\s+not\s+available" },
            // Nominet writes "Registered on:" in a record and "has not been registered" for a free
            // name, so the bare word "registered" cannot be the signal — it appears in both.
            [".uk"] = new[]
            {
                @"this\s+domain\s+has\s+been\s+registered",
                @"registered\s+on" + PatternCatalog.Separator,
                @"registrar" + PatternCatalog.Separator + @"\S",
            },
            [".de"] = new[]
            {
                "status" + PatternCatalog.Separator + "connect",
                StatusRegistered,
                StatusActive,
                "status" + PatternCatalog.Separator + "redemption",

                // DENIC only: "Status: invalid" means the name cannot be registered as spelled.
                // It is not a record, but it must never be read as availability either.
                "status" + PatternCatalog.Separator + "invalid",
            },
            [".it"] = new[] { StatusActive, StatusRegistered },
            [".fr"] = new[] { StatusActive, StatusRegistered },
            [".ca"] = new[] { @"domain\s+registered", StatusRegistered },
            [".nl"] = new[] { StatusActive, "status" + PatternCatalog.Separator + @"in\s+use" },
            [".be"] = new[] { StatusRegistered, "status" + PatternCatalog.Separator + "allocated" },
            [".dk"] = new[] { StatusActive },
            [".no"] = new[] { StatusActive },
            [".se"] = new[] { StatusActive },
            [".pt"] = new[] { StatusActive },
        };

        // Every remaining suffix in the reference table shares the same single pattern.
        const string Shared =
            ".eu .ch .li .at .fi .es .mx .ar .br .cl .pe .co .ve .ec .uy .py .bo .hn .ni .cr .gt .sv .pa " +
            ".do .pr .cu .tt .gy .sr .jm .bb .lc .gd .vc .dm .ag .kn .ai .ms .tc .vg .fk .gs .sh .pn .ki " +
            ".nr .tv .ws .cc .cx .hm .nf .sj .bv .tf .pm .wf .yt .re .mq .gp .gf .pf .nc .vu .tk .to .as " +
            ".fm .pw .cf .ml .ga .gq .cm .bi .ne .cd .dj .km .mg .rw .sc .so .st .tz .ug .zm .zw";

        foreach (var tld in Shared.Split(' '))
        {
            if (tld.Length > 0 && !table.ContainsKey(tld))
            {
                table[tld] = new[] { StatusRegistered };
            }
        }

        var compiled = new Dictionary<string, Regex[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in table)
        {
            compiled[entry.Key] = PatternCatalog.CompileAll(entry.Value);
        }

        return compiled;
    }
}

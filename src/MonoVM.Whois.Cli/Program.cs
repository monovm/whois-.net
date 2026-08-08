using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MonoVM.Whois;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Cli;

/// <summary>Command line front end for the library.</summary>
internal static class Program
{
    private const int ExitOk = 0;
    private const int ExitLookupFailed = 1;
    private const int ExitUsage = 2;

    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        var options = CommandLineOptions.Parse(args);

        if (options.Help || args.Length == 0)
        {
            PrintUsage();
            return options.Error is null ? ExitOk : ExitUsage;
        }

        if (options.Version)
        {
            Console.WriteLine(GetVersion());
            return ExitOk;
        }

        if (options.Error is not null)
        {
            Console.Error.WriteLine($"error: {options.Error}");
            Console.Error.WriteLine("Run 'monovm-whois --help' for usage.");
            return ExitUsage;
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        using var client = BuildClient(options);

        if (options.ListServers)
        {
            foreach (var tld in client.Servers.SupportedTlds)
            {
                Console.WriteLine(tld);
            }

            return ExitOk;
        }

        try
        {
            return options.Json
                ? await RunJsonAsync(client, options, cancellation.Token).ConfigureAwait(false)
                : await RunTableAsync(client, options, cancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("cancelled");
            return ExitLookupFailed;
        }
    }

    private static WhoisClient BuildClient(CommandLineOptions options)
    {
        var builder = WhoisClient.CreateBuilder();

        if (options.Tlds.Count > 0)
        {
            builder.WithPopularTlds(options.Tlds.ToArray());
        }

        if (options.Timeout.HasValue)
        {
            builder.WithWhois43Timeout(options.Timeout.Value).WithRdapTimeout(options.Timeout.Value);
        }

        if (options.NoCache)
        {
            builder.WithoutCache();
        }

        if (options.Parallelism.HasValue)
        {
            builder.WithMaxParallelism(options.Parallelism.Value);
        }

        if (options.ShowTrace)
        {
            builder.WithFullTrace();
        }

        builder.WithRecordParsing(options.ShowRecord || options.Json);

        return builder.Build();
    }

    private static async Task<int> RunTableAsync(
        WhoisClient client,
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        var failed = false;
        var rows = new List<(string Name, WhoisLookupResult Result)>();

        await foreach (var result in client.LookupManyAsync(options.Domains, cancellationToken).ConfigureAwait(false))
        {
            rows.Add((result.Name, result));
            failed |= result.Status is DomainAvailabilityStatus.Error or DomainAvailabilityStatus.Invalid;
        }

        var width = rows.Count == 0 ? 0 : rows.Max(row => row.Name.Length);

        foreach (var (name, result) in rows)
        {
            Write(name.PadRight(width), ConsoleColor.White);
            Console.Write("  ");
            Write(result.Status.ToWireString(), ColorFor(result.Status));

            if (result.Status is DomainAvailabilityStatus.Error or DomainAvailabilityStatus.Invalid)
            {
                Console.Write("  ");
                Console.Write(Shorten(result.Message));
            }
            else if (result.Record?.ExpiresOn is { } expiry)
            {
                Console.Write("  expires ");
                Console.Write(expiry.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            }

            Console.WriteLine();

            if (options.ShowTrace && result.Verdict is not null)
            {
                foreach (var trace in result.Verdict.Trace)
                {
                    Console.WriteLine($"    {trace}");
                }
            }

            if (options.ShowRecord && result.Record is not null && !result.Record.IsEmpty)
            {
                PrintRecord(result.Record);
            }

            if (options.ShowRaw && result.RawText is not null)
            {
                Console.WriteLine();
                Console.WriteLine(result.RawText.Trim());
                Console.WriteLine();
            }
        }

        return failed ? ExitLookupFailed : ExitOk;
    }

    private static async Task<int> RunJsonAsync(
        WhoisClient client,
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        var failed = false;
        var payload = new List<Dictionary<string, object?>>();

        await foreach (var result in client.LookupManyAsync(options.Domains, cancellationToken).ConfigureAwait(false))
        {
            failed |= result.Status is DomainAvailabilityStatus.Error or DomainAvailabilityStatus.Invalid;

            var entry = new Dictionary<string, object?>
            {
                ["domain"] = result.Name,
                ["status"] = result.Status.ToWireString(),
                ["available"] = result.IsAvailable,
                ["server"] = result.Server?.Host,
                ["durationMs"] = Math.Round(result.Duration.TotalMilliseconds, 1),
            };

            if (result.Verdict is not null)
            {
                entry["reason"] = result.Verdict.Reason;
                entry["decidedBy"] = result.Verdict.DecidedBy;
            }

            if (result.ErrorCode is not null)
            {
                entry["error"] = result.ErrorCode.ToString();
                entry["errorMessage"] = result.Message;
            }

            if (result.Record is { IsEmpty: false } record)
            {
                entry["record"] = new Dictionary<string, object?>
                {
                    ["domainName"] = record.DomainName,
                    ["registrar"] = record.Registrar,
                    ["createdOn"] = record.CreatedOn,
                    ["updatedOn"] = record.UpdatedOn,
                    ["expiresOn"] = record.ExpiresOn,
                    ["nameServers"] = record.NameServers,
                    ["statuses"] = record.Statuses,
                    ["dnssec"] = record.DnsSecEnabled,
                    ["registrant"] = Describe(record.Registrant),
                };
            }

            if (options.ShowRaw)
            {
                entry["raw"] = result.RawText;
            }

            payload.Add(entry);
        }

        Console.WriteLine(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        return failed ? ExitLookupFailed : ExitOk;
    }

    private static Dictionary<string, object?>? Describe(DomainContact? contact)
        => contact is null
            ? null
            : new Dictionary<string, object?>
            {
                ["name"] = contact.Name,
                ["organization"] = contact.Organization,
                ["email"] = contact.Email,
                ["country"] = contact.Country,
            };

    private static void PrintRecord(WhoisRecord record)
    {
        void Line(string label, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                Console.WriteLine($"    {label,-14}{value}");
            }
        }

        Line("registrar", record.Registrar);
        Line("created", record.CreatedOn?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Line("updated", record.UpdatedOn?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Line("expires", record.ExpiresOn?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Line("registrant", record.Registrant?.Organization ?? record.Registrant?.Name);
        Line("dnssec", record.DnsSecEnabled is null ? null : record.DnsSecEnabled.Value ? "signed" : "unsigned");

        if (record.NameServers.Count > 0)
        {
            Line("nameservers", string.Join(", ", record.NameServers));
        }

        if (record.Statuses.Count > 0)
        {
            Line("status", string.Join(", ", record.Statuses));
        }

        Console.WriteLine();
    }

    private static ConsoleColor ColorFor(DomainAvailabilityStatus status) => status switch
    {
        DomainAvailabilityStatus.Available => ConsoleColor.Green,
        DomainAvailabilityStatus.Registered => ConsoleColor.Yellow,
        DomainAvailabilityStatus.Premium => ConsoleColor.Magenta,
        DomainAvailabilityStatus.Invalid => ConsoleColor.DarkGray,
        _ => ConsoleColor.Red,
    };

    private static void Write(string text, ConsoleColor color)
    {
        if (Console.IsOutputRedirected)
        {
            Console.Write(text);
            return;
        }

        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = previous;
    }

    private static string Shorten(string message)
    {
        var line = message.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return line.Length <= 120 ? line : line.Substring(0, 117) + "...";
    }

    private static string GetVersion()
        => typeof(Program).GetTypeInfo().Assembly
               .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
           ?? "unknown";

    private static void PrintUsage()
    {
        Console.WriteLine(
            @"monovm-whois — domain WHOIS and RDAP lookups

usage:
  monovm-whois <domain>... [options]

arguments:
  <domain>          A domain name. Without a suffix, the popular ones are tried.
                    URLs, subdomains and internationalised names are all accepted.

options:
  --json            Emit JSON instead of a table.
  --record          Print the parsed registration record.
  --raw             Print the registry's reply verbatim.
  --trace           Show which rule decided each verdict.
  --tlds <list>     Comma-separated suffixes to try for a bare label (default: .com,.net,.org,.info).
  --timeout <secs>  Per-lookup timeout (default: 10 for WHOIS, 30 for RDAP).
  --parallel <n>    How many lookups to run at once (default: 8).
  --no-cache        Do not reuse replies within this run.
  --servers         List every suffix the bundled table serves.
  -v, --version     Print the version.
  -h, --help        Print this message.

exit codes:
  0  every name resolved to a verdict
  1  at least one lookup failed or was not usable
  2  the command line could not be read

examples:
  monovm-whois monovm.com
  monovm-whois monovm --tlds .com,.dev,.io
  monovm-whois example.co.uk --record
  monovm-whois münchen.de bücher.com --json");
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;

namespace MonoVM.Whois.Cli;

/// <summary>What the user asked for on the command line.</summary>
internal sealed class CommandLineOptions
{
    /// <summary>Domains to look up.</summary>
    public List<string> Domains { get; } = new List<string>();

    /// <summary>Suffixes to try for a bare label.</summary>
    public List<string> Tlds { get; } = new List<string>();

    /// <summary>Emit JSON rather than a table.</summary>
    public bool Json { get; private set; }

    /// <summary>Print the parsed record.</summary>
    public bool ShowRecord { get; private set; }

    /// <summary>Print the registry's reply verbatim.</summary>
    public bool ShowRaw { get; private set; }

    /// <summary>Print the rule that decided each verdict.</summary>
    public bool ShowTrace { get; private set; }

    /// <summary>List the suffixes the bundled table serves and exit.</summary>
    public bool ListServers { get; private set; }

    /// <summary>Print usage and exit.</summary>
    public bool Help { get; private set; }

    /// <summary>Print the version and exit.</summary>
    public bool Version { get; private set; }

    /// <summary>Skip the response cache.</summary>
    public bool NoCache { get; private set; }

    /// <summary>Per-lookup timeout.</summary>
    public TimeSpan? Timeout { get; private set; }

    /// <summary>How many lookups to run at once.</summary>
    public int? Parallelism { get; private set; }

    /// <summary>What went wrong while parsing the arguments.</summary>
    public string? Error { get; private set; }

    /// <summary>Reads the arguments.</summary>
    public static CommandLineOptions Parse(string[] args)
    {
        var options = new CommandLineOptions();

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            switch (arg)
            {
                case "-h":
                case "--help":
                    options.Help = true;
                    break;

                case "-v":
                case "--version":
                    options.Version = true;
                    break;

                case "--json":
                    options.Json = true;
                    break;

                case "--record":
                    options.ShowRecord = true;
                    break;

                case "--raw":
                    options.ShowRaw = true;
                    break;

                case "--trace":
                    options.ShowTrace = true;
                    break;

                case "--servers":
                    options.ListServers = true;
                    break;

                case "--no-cache":
                    options.NoCache = true;
                    break;

                case "--tlds":
                    if (!TryTake(args, ref i, out var tlds))
                    {
                        options.Error = "--tlds needs a comma-separated list of suffixes.";
                        return options;
                    }

                    foreach (var tld in tlds.Split(','))
                    {
                        if (!string.IsNullOrWhiteSpace(tld))
                        {
                            options.Tlds.Add(tld.Trim());
                        }
                    }

                    break;

                case "--timeout":
                    if (!TryTake(args, ref i, out var timeout) ||
                        !double.TryParse(timeout, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) ||
                        seconds <= 0)
                    {
                        options.Error = "--timeout needs a positive number of seconds.";
                        return options;
                    }

                    options.Timeout = TimeSpan.FromSeconds(seconds);
                    break;

                case "--parallel":
                    if (!TryTake(args, ref i, out var parallel) ||
                        !int.TryParse(parallel, NumberStyles.Integer, CultureInfo.InvariantCulture, out var degree) ||
                        degree < 1)
                    {
                        options.Error = "--parallel needs a positive whole number.";
                        return options;
                    }

                    options.Parallelism = degree;
                    break;

                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal))
                    {
                        options.Error = $"Unknown option '{arg}'.";
                        return options;
                    }

                    options.Domains.Add(arg);
                    break;
            }
        }

        if (options.Domains.Count == 0 && !options.Help && !options.Version && !options.ListServers)
        {
            options.Error = "Name at least one domain to look up.";
        }

        return options;
    }

    private static bool TryTake(string[] args, ref int index, out string value)
    {
        if (index + 1 >= args.Length)
        {
            value = string.Empty;
            return false;
        }

        value = args[++index];
        return true;
    }
}

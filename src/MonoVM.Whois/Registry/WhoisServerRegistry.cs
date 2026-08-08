using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Registry;

/// <summary>
/// The in-memory table of "which registry serves which suffix", built once from its sources.
/// </summary>
/// <remarks>
/// Immutable after construction and safe to share, which matters: parsing the bundled table costs
/// far more than a lookup does, so the registry is meant to be a singleton and the client holds one
/// for its lifetime.
/// </remarks>
public sealed class WhoisServerRegistry : IWhoisServerRegistry
{
    private readonly Dictionary<string, WhoisServerDefinition> _definitions;
    private readonly string[] _sortedTlds;

    /// <summary>Builds a registry from everything <paramref name="source"/> yields.</summary>
    /// <exception cref="WhoisDefinitionException">The source yielded nothing usable.</exception>
    public WhoisServerRegistry(IWhoisServerDefinitionSource source)
        : this((source ?? throw new ArgumentNullException(nameof(source))).Load(), source.Name)
    {
    }

    /// <summary>Builds a registry from a set of definitions.</summary>
    /// <exception cref="WhoisDefinitionException">The set is empty.</exception>
    public WhoisServerRegistry(IEnumerable<WhoisServerDefinition> definitions, string? sourceName = null)
    {
        if (definitions is null)
        {
            throw new ArgumentNullException(nameof(definitions));
        }

        _definitions = new Dictionary<string, WhoisServerDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var definition in definitions)
        {
            _definitions[definition.Tld] = definition;
        }

        if (_definitions.Count == 0)
        {
            throw new WhoisDefinitionException(
                $"No WHOIS server definitions were loaded from {sourceName ?? "the configured sources"}.");
        }

        _sortedTlds = _definitions.Keys.OrderBy(tld => tld, StringComparer.Ordinal).ToArray();
        SourceName = sourceName;
    }

    /// <summary>A registry over the bundled table alone.</summary>
    public static WhoisServerRegistry CreateDefault()
        => new WhoisServerRegistry(EmbeddedWhoisServerDefinitionSource.Instance);

    /// <summary>
    /// A registry assembled the way <paramref name="options"/> describes: the bundled table, then
    /// the file named by the environment variable, then the configured file, then any extra
    /// sources, then individual overrides — each layer winning over the one before it.
    /// </summary>
    public static WhoisServerRegistry FromOptions(WhoisOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        var sources = new List<IWhoisServerDefinitionSource>();

        if (options.UseBundledDefinitions)
        {
            sources.Add(EmbeddedWhoisServerDefinitionSource.Instance);
        }

        var fromEnvironment = Environment.GetEnvironmentVariable(WhoisOptions.DefinitionsEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            sources.Add(new JsonFileWhoisServerDefinitionSource(fromEnvironment!));
        }

        if (!string.IsNullOrWhiteSpace(options.DefinitionsFilePath))
        {
            sources.Add(new JsonFileWhoisServerDefinitionSource(options.DefinitionsFilePath!, required: true));
        }

        foreach (var source in options.AdditionalSources)
        {
            sources.Add(source);
        }

        if (options.AdditionalServers.Count > 0)
        {
            sources.Add(new InMemoryWhoisServerDefinitionSource(options.AdditionalServers, "options"));
        }

        var composite = new CompositeWhoisServerDefinitionSource(sources);
        return new WhoisServerRegistry(composite);
    }

    /// <summary>Where this registry's contents came from.</summary>
    public string? SourceName { get; }

    /// <summary>How many suffixes are served.</summary>
    public int Count => _definitions.Count;

    /// <inheritdoc />
    public IReadOnlyCollection<string> SupportedTlds => _sortedTlds;

    /// <summary>Every definition, ordered by suffix.</summary>
    public IEnumerable<WhoisServerDefinition> Definitions => _sortedTlds.Select(tld => _definitions[tld]);

    /// <inheritdoc />
    public bool Supports(string? tld) => TryGet(tld, out _);

    /// <inheritdoc />
    public bool TryGet(string? tld, [NotNullWhen(true)] out WhoisServerDefinition? definition)
    {
        definition = null;

        if (string.IsNullOrWhiteSpace(tld))
        {
            return false;
        }

        var key = DomainNameNormalizer.ToAscii(DomainName.NormalizeSuffix(tld));
        if (key.Length == 0)
        {
            return false;
        }

        return _definitions.TryGetValue(key, out definition);
    }

    /// <inheritdoc />
    public string? FindLongestSuffix(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return null;
        }

        var labels = DomainNameNormalizer.Normalize(host).Split('.');

        // Start with everything after the first label, which is the longest possible suffix, and
        // shorten from there. ".co.uk" therefore wins over ".uk" for example.co.uk.
        for (var index = 1; index < labels.Length; index++)
        {
            var candidate = "." + string.Join(".", labels, index, labels.Length - index);
            if (Supports(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}

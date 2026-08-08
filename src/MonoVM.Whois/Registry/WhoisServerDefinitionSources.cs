using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Registry;

/// <summary>The table of 870-odd suffixes shipped inside the package.</summary>
public sealed class EmbeddedWhoisServerDefinitionSource : IWhoisServerDefinitionSource
{
    internal const string ResourceName = "MonoVM.Whois.Data.whois-servers.json";

    private static readonly Lazy<IReadOnlyList<WhoisServerDefinition>> Cached =
        new Lazy<IReadOnlyList<WhoisServerDefinition>>(ReadResource, isThreadSafe: true);

    /// <summary>A shared instance; the table is parsed once per process.</summary>
    public static EmbeddedWhoisServerDefinitionSource Instance { get; } = new EmbeddedWhoisServerDefinitionSource();

    /// <inheritdoc />
    public string Name => "bundled";

    /// <inheritdoc />
    public IEnumerable<WhoisServerDefinition> Load() => Cached.Value;

    private static IReadOnlyList<WhoisServerDefinition> ReadResource()
    {
        var assembly = typeof(EmbeddedWhoisServerDefinitionSource).GetTypeInfo().Assembly;
        using var stream = assembly.GetManifestResourceStream(ResourceName);

        if (stream is null)
        {
            throw new WhoisDefinitionException(
                $"The bundled server table '{ResourceName}' is missing from the assembly.");
        }

        using var reader = new StreamReader(stream);
        return WhoisServerDefinitionJsonReader.Read(reader.ReadToEnd(), "bundled");
    }
}

/// <summary>A JSON table read from disk.</summary>
/// <remarks>
/// Missing files are tolerated by default: pointing at an override file that does not exist yet is
/// a normal state, not a configuration error.
/// </remarks>
public sealed class JsonFileWhoisServerDefinitionSource : IWhoisServerDefinitionSource
{
    private readonly string _path;
    private readonly bool _required;

    /// <summary>Creates the source.</summary>
    /// <param name="path">Path to the JSON file.</param>
    /// <param name="required">Whether a missing file is an error.</param>
    public JsonFileWhoisServerDefinitionSource(string path, bool required = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A definitions file path is required.", nameof(path));
        }

        _path = path;
        _required = required;
    }

    /// <inheritdoc />
    public string Name => Path.GetFileName(_path);

    /// <inheritdoc />
    public IEnumerable<WhoisServerDefinition> Load()
    {
        if (!File.Exists(_path))
        {
            if (_required)
            {
                throw new WhoisDefinitionException($"The definitions file '{_path}' does not exist.");
            }

            return Array.Empty<WhoisServerDefinition>();
        }

        string json;
        try
        {
            json = File.ReadAllText(_path);
        }
        catch (IOException exception)
        {
            throw new WhoisDefinitionException($"The definitions file '{_path}' could not be read: {exception.Message}", exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new WhoisDefinitionException($"The definitions file '{_path}' could not be read: {exception.Message}", exception);
        }

        return WhoisServerDefinitionJsonReader.Read(json, _path);
    }
}

/// <summary>A table held in memory, for tests and for programmatic overrides.</summary>
public sealed class InMemoryWhoisServerDefinitionSource : IWhoisServerDefinitionSource
{
    private readonly IReadOnlyList<WhoisServerDefinition> _definitions;

    /// <summary>Creates the source.</summary>
    public InMemoryWhoisServerDefinitionSource(IEnumerable<WhoisServerDefinition> definitions, string name = "in-memory")
    {
        if (definitions is null)
        {
            throw new ArgumentNullException(nameof(definitions));
        }

        _definitions = definitions.ToList();
        Name = name;
    }

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public IEnumerable<WhoisServerDefinition> Load() => _definitions;
}

/// <summary>A JSON table held as a string.</summary>
public sealed class JsonStringWhoisServerDefinitionSource : IWhoisServerDefinitionSource
{
    private readonly string _json;

    /// <summary>Creates the source.</summary>
    public JsonStringWhoisServerDefinitionSource(string json, string name = "inline")
    {
        _json = json ?? throw new ArgumentNullException(nameof(json));
        Name = name;
    }

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public IEnumerable<WhoisServerDefinition> Load() => WhoisServerDefinitionJsonReader.Read(_json, Name);
}

/// <summary>
/// Several sources treated as one, where a later source wins suffix by suffix.
/// </summary>
/// <remarks>
/// This is what makes overriding surgical: a file naming only <c>.com</c> replaces the bundled
/// <c>.com</c> entry and leaves the other eight hundred exactly as they were.
/// </remarks>
public sealed class CompositeWhoisServerDefinitionSource : IWhoisServerDefinitionSource
{
    private readonly IReadOnlyList<IWhoisServerDefinitionSource> _sources;

    /// <summary>Creates the composite.</summary>
    /// <param name="sources">Applied in order; later entries override earlier ones.</param>
    public CompositeWhoisServerDefinitionSource(params IWhoisServerDefinitionSource[] sources)
        : this((IEnumerable<IWhoisServerDefinitionSource>)sources)
    {
    }

    /// <inheritdoc cref="CompositeWhoisServerDefinitionSource(IWhoisServerDefinitionSource[])"/>
    public CompositeWhoisServerDefinitionSource(IEnumerable<IWhoisServerDefinitionSource> sources)
    {
        if (sources is null)
        {
            throw new ArgumentNullException(nameof(sources));
        }

        _sources = sources.Where(source => source is not null).ToList();
    }

    /// <inheritdoc />
    public string Name => _sources.Count == 0
        ? "composite(empty)"
        : "composite(" + string.Join(", ", _sources.Select(source => source.Name)) + ")";

    /// <summary>The sources being combined, in application order.</summary>
    public IReadOnlyList<IWhoisServerDefinitionSource> Sources => _sources;

    /// <inheritdoc />
    public IEnumerable<WhoisServerDefinition> Load()
    {
        var merged = new Dictionary<string, WhoisServerDefinition>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var source in _sources)
        {
            foreach (var definition in source.Load())
            {
                if (!merged.ContainsKey(definition.Tld))
                {
                    order.Add(definition.Tld);
                }

                merged[definition.Tld] = definition;
            }
        }

        foreach (var tld in order)
        {
            yield return merged[tld];
        }
    }
}

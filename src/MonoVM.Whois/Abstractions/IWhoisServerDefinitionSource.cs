using System.Collections.Generic;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>
/// Supplies server definitions from somewhere — the embedded table, a file on disk, a database, a
/// configuration section, a test fixture.
/// </summary>
/// <remarks>
/// This is the seam that keeps the registry closed for modification and open for extension: adding
/// a suffix, or repointing one at a different registry, never means editing this library. Sources
/// are combined by <see cref="Registry.CompositeWhoisServerDefinitionSource"/>, where a later
/// source overrides an earlier one entry by entry.
/// </remarks>
public interface IWhoisServerDefinitionSource
{
    /// <summary>A short name for this source, used in diagnostics and on each definition it yields.</summary>
    string Name { get; }

    /// <summary>Reads every definition this source knows about.</summary>
    /// <exception cref="Exceptions.WhoisDefinitionException">The source is malformed.</exception>
    IEnumerable<WhoisServerDefinition> Load();
}

using System;
using System.Diagnostics.CodeAnalysis;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>
/// Remembers replies for a while, so that a bulk check does not ask the same registry the same
/// question twice — which is also the quickest way to get rate-limited.
/// </summary>
public interface IWhoisResponseCache
{
    /// <summary>Fetches a cached reply, if one is still fresh.</summary>
    bool TryGet(string key, [NotNullWhen(true)] out WhoisResponse? response);

    /// <summary>Stores a reply under <paramref name="key"/> for <paramref name="lifetime"/>.</summary>
    void Set(string key, WhoisResponse response, TimeSpan lifetime);

    /// <summary>Forgets everything.</summary>
    void Clear();
}

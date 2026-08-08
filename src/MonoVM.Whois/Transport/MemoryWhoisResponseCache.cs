using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Transport;

/// <summary>
/// A bounded in-memory cache of replies.
/// </summary>
/// <remarks>
/// Deliberately small and dependency-free. Entries expire on read, and once the cache is full the
/// oldest quarter is dropped — good enough for the traffic a WHOIS client generates, and one less
/// package for a consumer to take. Swap in a real cache by implementing
/// <see cref="IWhoisResponseCache"/>.
/// </remarks>
public sealed class MemoryWhoisResponseCache : IWhoisResponseCache
{
    private readonly ConcurrentDictionary<string, Entry> _entries =
        new ConcurrentDictionary<string, Entry>(StringComparer.Ordinal);

    private readonly int _capacity;
    private readonly IClock _clock;

    /// <summary>Creates a cache holding at most <paramref name="capacity"/> replies.</summary>
    public MemoryWhoisResponseCache(int capacity = 2048)
        : this(capacity, SystemClock.Instance)
    {
    }

    internal MemoryWhoisResponseCache(int capacity, IClock clock)
    {
        if (capacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), capacity, "The cache must hold at least one entry.");
        }

        _capacity = capacity;
        _clock = clock;
    }

    /// <summary>How many entries are currently held, including any not yet evicted.</summary>
    public int Count => _entries.Count;

    /// <inheritdoc />
    public bool TryGet(string key, [NotNullWhen(true)] out WhoisResponse? response)
    {
        response = null;

        if (key is null || !_entries.TryGetValue(key, out var entry))
        {
            return false;
        }

        if (entry.ExpiresAt <= _clock.UtcNow)
        {
            _entries.TryRemove(key, out _);
            return false;
        }

        response = entry.Response;
        return true;
    }

    /// <inheritdoc />
    public void Set(string key, WhoisResponse response, TimeSpan lifetime)
    {
        if (key is null || response is null || lifetime <= TimeSpan.Zero)
        {
            return;
        }

        if (_entries.Count >= _capacity)
        {
            Evict();
        }

        _entries[key] = new Entry(response, _clock.UtcNow.Add(lifetime));
    }

    /// <inheritdoc />
    public void Clear() => _entries.Clear();

    private void Evict()
    {
        var now = _clock.UtcNow;

        var expired = _entries.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToList();
        foreach (var key in expired)
        {
            _entries.TryRemove(key, out _);
        }

        if (_entries.Count < _capacity)
        {
            return;
        }

        // Still full: drop the quarter closest to expiry.
        var victims = _entries
            .OrderBy(pair => pair.Value.ExpiresAt)
            .Take(Math.Max(1, _capacity / 4))
            .Select(pair => pair.Key)
            .ToList();

        foreach (var key in victims)
        {
            _entries.TryRemove(key, out _);
        }
    }

    private readonly struct Entry
    {
        public Entry(WhoisResponse response, DateTimeOffset expiresAt)
        {
            Response = response;
            ExpiresAt = expiresAt;
        }

        public WhoisResponse Response { get; }

        public DateTimeOffset ExpiresAt { get; }
    }
}

/// <summary>A cache that remembers nothing.</summary>
public sealed class NullWhoisResponseCache : IWhoisResponseCache
{
    /// <summary>The shared instance.</summary>
    public static readonly NullWhoisResponseCache Instance = new NullWhoisResponseCache();

    /// <inheritdoc />
    public bool TryGet(string key, [NotNullWhen(true)] out WhoisResponse? response)
    {
        response = null;
        return false;
    }

    /// <inheritdoc />
    public void Set(string key, WhoisResponse response, TimeSpan lifetime)
    {
    }

    /// <inheritdoc />
    public void Clear()
    {
    }
}

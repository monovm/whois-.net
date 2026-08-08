using System;

namespace MonoVM.Whois.Internal;

/// <summary>A source of the current time, so expiry and pacing can be tested without waiting.</summary>
internal interface IClock
{
    DateTimeOffset UtcNow { get; }
}

/// <summary>The real clock.</summary>
internal sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new SystemClock();

    private SystemClock()
    {
    }

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

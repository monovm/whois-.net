using System;

namespace MonoVM.Whois.Model;

/// <summary>The verdict of a lookup.</summary>
/// <remarks>
/// <see cref="Error"/> is deliberately not folded into <see cref="Available"/>. A rate-limited or
/// blocked server tells you nothing about the domain, and reporting a registered name as free is
/// the one mistake this library must never make.
/// </remarks>
public enum DomainAvailabilityStatus
{
    /// <summary>The lookup produced no usable verdict.</summary>
    Unknown = 0,

    /// <summary>The registry says the name is not registered.</summary>
    Available = 1,

    /// <summary>The name is registered.</summary>
    Registered = 2,

    /// <summary>The registry flagged the name as premium or reserved; it is not free to register.</summary>
    Premium = 3,

    /// <summary>Not a usable domain name, or no WHOIS/RDAP server is known for the suffix.</summary>
    Invalid = 4,

    /// <summary>The lookup failed or the server declined to answer. Retry; never a verdict.</summary>
    Error = 5,
}

/// <summary>Conversions for <see cref="DomainAvailabilityStatus"/>.</summary>
public static class DomainAvailabilityStatusExtensions
{
    /// <summary>
    /// Renders the status as its lower-case wire wording: <c>available</c>, <c>unavailable</c>,
    /// <c>premium</c>, <c>invalid</c>, <c>error</c> or <c>unknown</c>.
    /// </summary>
    public static string ToWireString(this DomainAvailabilityStatus status) => status switch
    {
        DomainAvailabilityStatus.Available => "available",
        DomainAvailabilityStatus.Registered => "unavailable",
        DomainAvailabilityStatus.Premium => "premium",
        DomainAvailabilityStatus.Invalid => "invalid",
        DomainAvailabilityStatus.Error => "error",
        DomainAvailabilityStatus.Unknown => "unknown",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, null),
    };
}

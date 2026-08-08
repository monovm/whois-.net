using System;
using MonoVM.Whois.Detection;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois;

/// <summary>
/// Everything one lookup produced: the verdict, the reasoning behind it, the parsed record and the
/// reply it all came from.
/// </summary>
/// <remarks>
/// A failed lookup is a result, not an exception — by default. A bulk check of a thousand names
/// will hit a rate limit somewhere, and unwinding the stack for it would throw away the nine
/// hundred and ninety-nine that worked. Set
/// <see cref="Configuration.WhoisOptions.ThrowOnLookupFailure"/> if you would rather have the
/// exception.
/// </remarks>
public sealed class WhoisLookupResult
{
    private WhoisLookupResult(string query, DomainAvailabilityStatus status, string message)
    {
        Query = query;
        Status = status;
        Message = message;
    }

    /// <summary>The string the caller asked about.</summary>
    public string Query { get; }

    /// <summary>The parsed name, when the input could be read as one.</summary>
    public DomainName? Domain { get; private init; }

    /// <summary>The verdict.</summary>
    public DomainAvailabilityStatus Status { get; }

    /// <summary>A sentence describing the outcome; the record itself when the name is registered.</summary>
    public string Message { get; }

    /// <summary>The registry's reply, verbatim.</summary>
    public string? RawText { get; private init; }

    /// <summary>The parsed record, when the reply carried one and parsing was enabled.</summary>
    public WhoisRecord? Record { get; private init; }

    /// <summary>How the verdict was reached.</summary>
    public AvailabilityVerdict? Verdict { get; private init; }

    /// <summary>Which registry was asked.</summary>
    public WhoisServerDefinition? Server { get; private init; }

    /// <summary>How long the lookup took, including retries and referrals.</summary>
    public TimeSpan Duration { get; private init; }

    /// <summary>Whether the reply came from the cache rather than the network.</summary>
    public bool FromCache { get; private init; }

    /// <summary>What went wrong, when something did.</summary>
    public WhoisErrorCode? ErrorCode { get; private init; }

    /// <summary>The exception behind <see cref="ErrorCode"/>, when there was one.</summary>
    public WhoisException? Error { get; private init; }

    /// <summary>True when the registry says the name is free to register.</summary>
    public bool IsAvailable => Status == DomainAvailabilityStatus.Available;

    /// <summary>True when the name is taken.</summary>
    public bool IsRegistered => Status == DomainAvailabilityStatus.Registered;

    /// <summary>True when the registry is holding the name back as premium or reserved.</summary>
    public bool IsPremium => Status == DomainAvailabilityStatus.Premium;

    /// <summary>True when the lookup produced a verdict rather than a failure.</summary>
    public bool Succeeded => Status is DomainAvailabilityStatus.Available
        or DomainAvailabilityStatus.Registered
        or DomainAvailabilityStatus.Premium;

    /// <summary>The name that was looked up, or the raw query when it could not be parsed.</summary>
    public string Name => Domain?.Unicode ?? Query;

    /// <summary>Builds a result for input that is not a usable domain name.</summary>
    public static WhoisLookupResult Invalid(string query, string message, DomainName? domain = null)
        => new WhoisLookupResult(query, DomainAvailabilityStatus.Invalid, message)
        {
            Domain = domain,
            ErrorCode = WhoisErrorCode.InvalidDomain,
        };

    /// <summary>Builds a result for a lookup that could not be completed.</summary>
    public static WhoisLookupResult Failed(
        string query,
        DomainName? domain,
        WhoisException error,
        WhoisServerDefinition? server = null,
        TimeSpan duration = default)
        => new WhoisLookupResult(query, DomainAvailabilityStatus.Error, error.Message)
        {
            Domain = domain,
            Server = server,
            Duration = duration,
            ErrorCode = error.Code,
            Error = error,
        };

    /// <summary>Builds a result from a reply and the verdict drawn from it.</summary>
    public static WhoisLookupResult FromResponse(
        string query,
        WhoisResponse response,
        AvailabilityVerdict verdict,
        WhoisServerDefinition server,
        WhoisRecord? record,
        TimeSpan duration)
    {
        if (response is null)
        {
            throw new ArgumentNullException(nameof(response));
        }

        if (verdict is null)
        {
            throw new ArgumentNullException(nameof(verdict));
        }

        var name = response.Domain.Unicode;

        var message = verdict.Status switch
        {
            DomainAvailabilityStatus.Available => $"{name} is available for registration.",
            DomainAvailabilityStatus.Premium => $"{name} is held back by the registry as a premium or reserved name.",
            DomainAvailabilityStatus.Error => verdict.Reason,
            _ => response.Text,
        };

        return new WhoisLookupResult(query, verdict.Status, message)
        {
            Domain = response.Domain,
            RawText = response.Text,
            Record = record,
            Verdict = verdict,
            Server = server,
            Duration = duration,
            FromCache = response.FromCache,
            ErrorCode = verdict.Status == DomainAvailabilityStatus.Error ? WhoisErrorCode.ServerRefused : null,
        };
    }

    /// <inheritdoc />
    public override string ToString() => $"{Name}: {Status.ToWireString()}";
}

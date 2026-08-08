using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>Base class for every error this library raises.</summary>
/// <remarks>
/// Catching <see cref="WhoisException"/> catches all of them; the derived types let callers that
/// care tell a misconfigured suffix apart from a registry that is merely rate-limiting them.
/// </remarks>
public class WhoisException : Exception
{
    /// <summary>Creates the exception.</summary>
    public WhoisException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public WhoisException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }

    /// <summary>A stable, machine-readable classification of the failure.</summary>
    public virtual WhoisErrorCode Code => WhoisErrorCode.Unknown;
}

/// <summary>Machine-readable classification of a failed lookup.</summary>
public enum WhoisErrorCode
{
    /// <summary>No more specific classification applies.</summary>
    Unknown = 0,

    /// <summary>The input is not a usable domain name.</summary>
    InvalidDomain = 1,

    /// <summary>No WHOIS or RDAP server is known for the suffix.</summary>
    UnsupportedTld = 2,

    /// <summary>The server could not be reached, or the connection failed mid-exchange.</summary>
    Connection = 3,

    /// <summary>The server was reached but declined to answer: rate limit, block, or 5xx.</summary>
    ServerRefused = 4,

    /// <summary>The server answered with nothing at all.</summary>
    EmptyResponse = 5,

    /// <summary>The server definition file is missing, malformed or contradictory.</summary>
    Definition = 6,

    /// <summary>The operation was cancelled or timed out.</summary>
    Timeout = 7,
}

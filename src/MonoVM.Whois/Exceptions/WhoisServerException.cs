using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>
/// The server was reached and answered, but refused to give a verdict: it is rate-limiting,
/// blocking the client, or has retired port 43 in favour of RDAP.
/// </summary>
/// <remarks>
/// This is the exception that keeps the library honest. Every one of these replies contains no
/// registration fields, so treating "no record" as "not registered" would report a registered
/// domain as free to register.
/// </remarks>
public sealed class WhoisServerException : WhoisException
{
    /// <summary>Creates the exception.</summary>
    public WhoisServerException(string message, string? server = null, int? httpStatusCode = null, Exception? innerException = null)
        : base(message, innerException)
    {
        Server = server;
        HttpStatusCode = httpStatusCode;
    }

    /// <summary>The host or URL that declined.</summary>
    public string? Server { get; }

    /// <summary>The HTTP status for an RDAP refusal; <see langword="null"/> for port 43.</summary>
    public int? HttpStatusCode { get; }

    /// <summary>True when retrying later has a reasonable chance of succeeding.</summary>
    public bool IsTransient { get; init; } = true;

    /// <inheritdoc />
    public override WhoisErrorCode Code => WhoisErrorCode.ServerRefused;
}

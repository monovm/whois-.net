using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>The registry could not be reached, or the exchange failed part-way through.</summary>
public sealed class WhoisConnectionException : WhoisException
{
    /// <summary>Creates the exception.</summary>
    public WhoisConnectionException(string message, string? server = null, Exception? innerException = null)
        : base(message, innerException)
        => Server = server;

    /// <summary>The host that could not be reached.</summary>
    public string? Server { get; }

    /// <summary>True when the failure was a timeout rather than a refusal or a DNS error.</summary>
    public bool IsTimeout { get; init; }

    /// <inheritdoc />
    public override WhoisErrorCode Code => IsTimeout ? WhoisErrorCode.Timeout : WhoisErrorCode.Connection;
}

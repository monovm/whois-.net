using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>No server is known for the suffix, or the server reached does not serve it.</summary>
public sealed class UnsupportedTldException : WhoisException
{
    /// <summary>Creates the exception.</summary>
    public UnsupportedTldException(string message, string? tld = null, Exception? innerException = null)
        : base(message, innerException)
        => Tld = tld;

    /// <summary>The suffix that could not be served.</summary>
    public string? Tld { get; }

    /// <inheritdoc />
    public override WhoisErrorCode Code => WhoisErrorCode.UnsupportedTld;
}

using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>The string handed in is not a usable domain name.</summary>
public sealed class InvalidDomainException : WhoisException
{
    /// <summary>Creates the exception.</summary>
    public InvalidDomainException(string message, string? input = null, Exception? innerException = null)
        : base(message, innerException)
        => Input = input;

    /// <summary>The offending input, when it is safe to echo back.</summary>
    public string? Input { get; }

    /// <inheritdoc />
    public override WhoisErrorCode Code => WhoisErrorCode.InvalidDomain;
}

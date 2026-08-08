using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>A server definition file is missing, malformed, or describes an unusable endpoint.</summary>
public sealed class WhoisDefinitionException : WhoisException
{
    /// <summary>Creates the exception.</summary>
    public WhoisDefinitionException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }

    /// <inheritdoc />
    public override WhoisErrorCode Code => WhoisErrorCode.Definition;
}

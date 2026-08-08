using System;

namespace MonoVM.Whois.Exceptions;

/// <summary>
/// The server answered with nothing at all.
/// </summary>
/// <remarks>
/// Raised rather than guessed at: an empty reply is not evidence that a domain is unregistered.
/// The few registries for which it genuinely is opt in per suffix with
/// <see cref="Model.WhoisServerDefinition.AvailableWhenEmpty"/>.
/// </remarks>
public sealed class EmptyWhoisResponseException : WhoisException
{
    /// <summary>Creates the exception.</summary>
    public EmptyWhoisResponseException(string message, string? server = null, Exception? innerException = null)
        : base(message, innerException)
        => Server = server;

    /// <summary>The host that answered with nothing.</summary>
    public string? Server { get; }

    /// <inheritdoc />
    public override WhoisErrorCode Code => WhoisErrorCode.EmptyResponse;
}

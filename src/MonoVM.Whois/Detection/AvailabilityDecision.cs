namespace MonoVM.Whois.Detection;

/// <summary>What a single detection rule concluded.</summary>
public enum AvailabilityDecision
{
    /// <summary>This rule has no opinion; hand the response to the next rule.</summary>
    Continue = 0,

    /// <summary>The registry says the name is not registered.</summary>
    Available = 1,

    /// <summary>The name is registered.</summary>
    Registered = 2,

    /// <summary>The registry flagged the name as premium or reserved.</summary>
    Premium = 3,

    /// <summary>The server declined to answer; the reply carries no verdict at all.</summary>
    Refused = 4,

    /// <summary>The server reached does not serve this suffix.</summary>
    Unsupported = 5,
}

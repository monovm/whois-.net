namespace MonoVM.Whois.Model;

/// <summary>The wire protocol a registry is queried with.</summary>
public enum WhoisProtocol
{
    /// <summary>The classic line-oriented WHOIS protocol on TCP port 43 (RFC 3912).</summary>
    Whois43 = 0,

    /// <summary>The JSON-over-HTTPS Registration Data Access Protocol (RFC 7482/7483).</summary>
    Rdap = 1,
}

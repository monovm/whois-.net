using MonoVM.Whois.Model;

namespace MonoVM.Whois.Abstractions;

/// <summary>Turns a raw reply into a <see cref="WhoisRecord"/>.</summary>
/// <remarks>
/// Separate from the availability analyzer on purpose: a reply can be perfectly parseable and still
/// carry no verdict, and a verdict can be reached from a reply that has no record to parse.
/// </remarks>
public interface IWhoisRecordParser
{
    /// <summary>True when this parser recognises the shape of <paramref name="response"/>.</summary>
    bool CanParse(WhoisResponse response);

    /// <summary>
    /// Parses <paramref name="response"/>. Returns <see cref="WhoisRecord.Empty"/> rather than
    /// throwing when the reply carries no record: an unparseable reply is not an exceptional event.
    /// </summary>
    WhoisRecord Parse(WhoisResponse response);
}

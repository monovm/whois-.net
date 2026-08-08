using System;
using System.Collections.Generic;
using System.Linq;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Parsing;

/// <summary>
/// Hands a reply to the first parser that recognises its shape.
/// </summary>
/// <remarks>
/// The client depends on this rather than on either concrete parser, so supporting a new reply
/// format — a registry with a genuinely unusual layout, say — means adding a parser to the list and
/// nothing else.
/// </remarks>
public sealed class CompositeWhoisRecordParser : IWhoisRecordParser
{
    private readonly IWhoisRecordParser[] _parsers;

    /// <summary>Creates a composite over <paramref name="parsers"/>, tried in order.</summary>
    public CompositeWhoisRecordParser(params IWhoisRecordParser[] parsers)
        : this((IEnumerable<IWhoisRecordParser>)parsers)
    {
    }

    /// <inheritdoc cref="CompositeWhoisRecordParser(IWhoisRecordParser[])"/>
    public CompositeWhoisRecordParser(IEnumerable<IWhoisRecordParser> parsers)
    {
        if (parsers is null)
        {
            throw new ArgumentNullException(nameof(parsers));
        }

        _parsers = parsers.Where(parser => parser is not null).ToArray();

        if (_parsers.Length == 0)
        {
            throw new ArgumentException("At least one parser is required.", nameof(parsers));
        }
    }

    /// <summary>A composite over the parsers shipped with the library.</summary>
    public static CompositeWhoisRecordParser CreateDefault()
        => new CompositeWhoisRecordParser(new RdapRecordParser(), new KeyValueWhoisRecordParser());

    /// <summary>The parsers being tried, in order.</summary>
    public IReadOnlyList<IWhoisRecordParser> Parsers => _parsers;

    /// <inheritdoc />
    public bool CanParse(WhoisResponse response) => _parsers.Any(parser => parser.CanParse(response));

    /// <inheritdoc />
    public WhoisRecord Parse(WhoisResponse response)
    {
        if (response is null)
        {
            throw new ArgumentNullException(nameof(response));
        }

        foreach (var parser in _parsers)
        {
            if (parser.CanParse(response))
            {
                return parser.Parse(response);
            }
        }

        return WhoisRecord.Empty;
    }
}

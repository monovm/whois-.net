using System.Collections.Generic;
using System.Text.Json;
using MonoVM.Whois.Exceptions;
using MonoVM.Whois.Internal;
using MonoVM.Whois.Model;

namespace MonoVM.Whois.Registry;

/// <summary>
/// Reads the JSON format the server table is written in, wherever it comes from.
/// </summary>
/// <remarks>
/// <para>
/// The format is a flat array, one object per group of suffixes that share a registry:
/// </para>
/// <code language="json">
/// [
///   {
///     "extensions": ".com,.net",
///     "uri": "socket://whois.verisign-grs.com",
///     "available": "No match for",
///     "premium": "Reserved by the registry",
///     "available_when_empty": "false",
///     "comment": "why this entry looks the way it does"
///   }
/// ]
/// </code>
/// <para>
/// Values are read leniently — a flag may be written as a JSON boolean or as the string
/// <c>"true"</c> — because these files are maintained by hand.
/// </para>
/// </remarks>
public static class WhoisServerDefinitionJsonReader
{
    /// <summary>Parses the table in <paramref name="json"/>.</summary>
    /// <param name="json">The document text.</param>
    /// <param name="sourceName">Name recorded on each definition, and quoted in error messages.</param>
    /// <exception cref="WhoisDefinitionException">The document is not a usable server table.</exception>
    public static IReadOnlyList<WhoisServerDefinition> Read(string json, string sourceName)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new WhoisDefinitionException($"{sourceName} is empty.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            });
        }
        catch (JsonException exception)
        {
            throw new WhoisDefinitionException($"{sourceName} is not valid JSON: {exception.Message}", exception);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                throw new WhoisDefinitionException(
                    $"{sourceName} must contain a JSON array of server definitions, but its root is {document.RootElement.ValueKind}.");
            }

            var definitions = new List<WhoisServerDefinition>();
            var index = 0;

            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    throw new WhoisDefinitionException(
                        $"{sourceName}: entry {index} must be a JSON object, but it is {element.ValueKind}.");
                }

                ReadEntry(element, sourceName, index, definitions);
                index++;
            }

            if (definitions.Count == 0)
            {
                throw new WhoisDefinitionException($"{sourceName} contains no server definitions.");
            }

            return definitions;
        }
    }

    private static void ReadEntry(
        JsonElement element,
        string sourceName,
        int index,
        ICollection<WhoisServerDefinition> definitions)
    {
        var extensions = ReadString(element, "extensions");
        if (string.IsNullOrWhiteSpace(extensions))
        {
            throw new WhoisDefinitionException($"{sourceName}: entry {index} names no extensions.");
        }

        var uri = ReadString(element, "uri");
        if (string.IsNullOrWhiteSpace(uri))
        {
            throw new WhoisDefinitionException($"{sourceName}: entry {index} ({extensions}) names no uri.");
        }

        var available = ReadString(element, "available");
        var premium = ReadString(element, "premium");
        var availableWhenEmpty = ReadString(element, "available_when_empty").ToFlag();
        var comment = ReadString(element, "comment");

        foreach (var extension in extensions!.Split(','))
        {
            var suffix = DomainName.NormalizeSuffix(extension);
            if (suffix.Length == 0)
            {
                continue;
            }

            definitions.Add(WhoisServerDefinition.Create(
                suffix, uri!, available, premium, availableWhenEmpty, comment, sourceName));
        }
    }

    private static string ReadString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            return string.Empty;
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                return value.GetString() ?? string.Empty;
            case JsonValueKind.True:
                return "true";
            case JsonValueKind.False:
                return "false";
            case JsonValueKind.Number:
                return value.GetRawText();
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                return string.Empty;
            default:
                return value.GetRawText();
        }
    }

    /// <summary>Writes definitions back out in the same format, for tooling and round-tripping.</summary>
    public static string Write(IEnumerable<WhoisServerDefinition> definitions)
    {
        var buffer = new System.IO.MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartArray();

            foreach (var definition in definitions)
            {
                writer.WriteStartObject();
                writer.WriteString("extensions", definition.Tld);
                writer.WriteString("uri", definition.Uri);

                if (definition.AvailableMatch is not null)
                {
                    writer.WriteString("available", definition.AvailableMatch);
                }

                if (definition.PremiumMatch is not null)
                {
                    writer.WriteString("premium", definition.PremiumMatch);
                }

                if (definition.AvailableWhenEmpty)
                {
                    writer.WriteString("available_when_empty", "true");
                }

                if (definition.Comment is not null)
                {
                    writer.WriteString("comment", definition.Comment);
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }
}

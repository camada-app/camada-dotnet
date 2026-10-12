// Redaction, non-configurable-off. The SDK never ships: Authorization/Cookie values (scheme
// only, Events/Builder.cs), body field values (shape only), query params that look like
// credentials, or raw user identifiers (HMAC-hashed here, inside the SDK, before anything
// reaches the queue). Ported from @camada/core src/redact.ts.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Camada;

public static partial class Redact
{
    [GeneratedRegex("(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NameRe();

    [GeneratedRegex("^eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}", RegexOptions.CultureInvariant)]
    private static partial Regex JwtRe();

    [GeneratedRegex("^[a-f0-9]{32,}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HexRe();

    [GeneratedRegex("^[A-Za-z0-9+/_-]{40,}={0,2}$", RegexOptions.CultureInvariant)]
    private static partial Regex B64Re();

    public static readonly string[] RedactAllowlist = { "plan", "role", "locale", "ab_variant" };   // additions only, never narrowing

    private static bool SuspectValue(string v) => JwtRe().IsMatch(v) || HexRe().IsMatch(v) || B64Re().IsMatch(v);

    /// <summary>A URL (a Referer) with its query and fragment run through ScrubQuery (camada-all-ijsa); the
    /// scheme, host and path are kept as they are. The path gets the same treatment as the request's own path
    /// `p` (none): a same-origin Referer's path already shipped as `p` on that page's own event, and a
    /// cross-origin one carries only the origin under the browsers' default policy.</summary>
    public static string? ScrubUrl(string? url)
    {
        if (url == null)
        {
            return null;
        }
        var hash = url.IndexOf('#');
        var head = hash == -1 ? url : url[..hash];
        var q = head.IndexOf('?');
        var scrubbed = q == -1 ? head : head[..q] + ScrubQuery(head[q..]);
        return hash == -1 ? scrubbed : scrubbed + "#" + ScrubQuery(url[(hash + 1)..]);
    }

    /// <summary>Replaces credential-looking query values with ~r, preserving structure and order.</summary>
    public static string ScrubQuery(string? query)
    {
        if (string.IsNullOrEmpty(query) || query.Length <= 1)
        {
            return query ?? "";
        }
        var lead = query[0] == '?' ? "?" : "";
        var parts = (lead.Length > 0 ? query[1..] : query).Split('&');
        var sb = new StringBuilder(lead);
        for (var i = 0; i < parts.Length; i++)
        {
            if (i > 0)
            {
                sb.Append('&');
            }
            var p = parts[i];
            var eq = p.IndexOf('=');
            if (eq == -1)
            {
                sb.Append(p);
                continue;
            }
            var name = p[..eq];
            var value = p[(eq + 1)..];
            sb.Append(NameRe().IsMatch(name) || SuspectValue(value) ? name + "=~r" : p);
        }
        return sb.ToString();
    }

    /// <summary>Body shape only: field names and byte sizes, never values. One level deep.</summary>
    public static Dictionary<string, int>? BodyShape(JsonElement obj)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        var outMap = new Dictionary<string, int>();
        foreach (var prop in obj.EnumerateObject())
        {
            outMap[prop.Name] = prop.Value.ValueKind switch
            {
                JsonValueKind.String => prop.Value.GetString()!.Length,
                JsonValueKind.Null or JsonValueKind.Undefined => 0,
                _ => prop.Value.GetRawText().Length,
            };
        }
        return outMap;
    }

    /// <summary>Stable per-tenant pseudonym: HMAC-SHA256 keyed by the ingest token, labelled so the hash
    /// can never double as anything else, truncated to 32 hex chars. The raw identifier never leaves.</summary>
    public static string HashUserId(string userId, string ingestToken)
    {
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(ingestToken), Encoding.UTF8.GetBytes("uid:" + userId));
        return Convert.ToHexString(mac).ToLowerInvariant()[..32];
    }
}

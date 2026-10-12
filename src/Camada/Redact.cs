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
    // Exact patterns of C6 v3. NameRe runs on ASCII-lowercased text (NameHit), so there is no case folding at all
    // (IgnoreCase would fold the Kelvin sign to k even with CultureInvariant); classes are explicit ASCII; `\A`/`\z`
    // are true string anchors (`$` would match before a trailing newline).
    [GeneratedRegex("(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)", RegexOptions.CultureInvariant)]
    private static partial Regex NameRe();

    [GeneratedRegex("\\AeyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}", RegexOptions.CultureInvariant)]
    private static partial Regex JwtRe();

    [GeneratedRegex("\\A[a-fA-F0-9]{32,}\\z", RegexOptions.CultureInvariant)]
    private static partial Regex HexRe();

    [GeneratedRegex("\\A[A-Za-z0-9+/_-]{40,}={0,2}\\z", RegexOptions.CultureInvariant)]
    private static partial Regex B64Re();

    public static readonly string[] RedactAllowlist = { "plan", "role", "locale", "ab_variant" };   // additions only, never narrowing

    private static bool SuspectValue(string v) => JwtRe().IsMatch(v) || HexRe().IsMatch(v) || B64Re().IsMatch(v);

    /// <summary>Lowercase A-Z only, then a substring search: ASCII-only case folding by construction.</summary>
    private static bool NameHit(string n)
    {
        var c = n.ToCharArray();
        for (var i = 0; i < c.Length; i++)
        {
            if (c[i] is >= 'A' and <= 'Z')
            {
                c[i] = (char)(c[i] + 32);
            }
        }
        return NameRe().IsMatch(new string(c));
    }

    // ASCII hex only, never a culture- or Unicode-aware digit test
    private static int HexVal(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };

    private static bool HasEscape(string s)
    {
        for (var i = s.IndexOf('%'); i >= 0 && i + 2 < s.Length; i = s.IndexOf('%', i + 1))
        {
            if (HexVal(s[i + 1]) >= 0 && HexVal(s[i + 2]) >= 0)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Percent-decoding that never throws: each `%HH` (ASCII hex) becomes the char with that byte's value
    /// (Latin-1), any other `%` stays, `+` stays. Up to 4 passes; text still holding a `%HH` after them is null
    /// (scrubbed). Never Uri.UnescapeDataString/WebUtility.UrlDecode. Only ever used to TEST a part.</summary>
    internal static string? Decode(string s)
    {
        for (var pass = 0; pass < 4 && HasEscape(s); pass++)
        {
            var b = new StringBuilder(s.Length);
            var i = 0;
            while (i < s.Length)
            {
                int hi, lo;
                if (s[i] == '%' && i + 2 < s.Length && (hi = HexVal(s[i + 1])) >= 0 && (lo = HexVal(s[i + 2])) >= 0)
                {
                    b.Append((char)(hi * 16 + lo));
                    i += 3;
                }
                else
                {
                    b.Append(s[i]);
                    i++;
                }
            }
            s = b.ToString();
        }
        return HasEscape(s) ? null : s;
    }

    /// <summary>One `name=value` or bare segment of a decoded nested value: a credential?</summary>
    private static bool CredSegment(string seg)
    {
        var eq = seg.IndexOf('=');
        return eq == -1 ? SuspectValue(seg) : NameHit(seg[..eq]) || SuspectValue(seg[(eq + 1)..]);
    }

    /// <summary>A decoded value carrying `?`, `&amp;` or `=` is a credential when one of its `[?&amp;]` segments is
    /// (C6 v3). No further decoding, no recursion.</summary>
    private static bool NestedCred(string d) => d.IndexOfAny(['?', '&', '=']) != -1 && d.Split('?', '&').Any(CredSegment);

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

    /// <summary>Replaces credential-looking query parts with ~r, preserving structure and order (C6 v3). The string
    /// is split on `&amp;`, never URL-parsed. Each part's name and value are percent-decoded before testing.
    /// `name=value` → `name=~r` when the name looks like a credential, the value looks like one, or the value holds a
    /// nested query with a credential segment (replaced whole, so payloads like `q=1' or '1'='1` stay visible to the
    /// scorer). A bare part → `~r` when it looks like a credential value or holds a credential segment. Either half
    /// still encoded after 4 decode passes counts as a credential. The output keeps the raw text.</summary>
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
                var d = Decode(p);
                sb.Append(d == null || SuspectValue(d) || NestedCred(d) ? "~r" : p);
                continue;
            }
            var name = p[..eq];
            var dn = Decode(name);
            var dv = Decode(p[(eq + 1)..]);
            sb.Append(dn == null || dv == null || NameHit(dn) || SuspectValue(dv) || NestedCred(dv) ? name + "=~r" : p);
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

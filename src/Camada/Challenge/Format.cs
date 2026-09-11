// Wire constants and pure helpers for the SDK-served challenge (contracts §D2), ported from
// @camada/core src/challenge/format.ts. Nothing here does crypto; Kit.cs supplies HMAC and
// SHA-256 from the BCL, so the format has exactly one definition across the family.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Camada.Challenge;

public static class Format
{
    public const string ChallengeCookie = "_cch";
    public const long ChallengeTtlMs = 3_600_000;   // 1 h (contract)
    public const int PowBits = 16;                  // leading zero bits of SHA-256($"{nonce}.{solution}")
    public const int NonceHex = 32;                 // the nonce is the first 32 hex chars of the HMAC
    private const long DayMs = 86_400_000;
    private const int MaxReturnTo = 2048;
    private const int MaxSolution = 32;

    public static long UtcDay(long nowMs) => nowMs / DayMs;

    // Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
    public static string NonceMessage(string? ip, long day) => $"camada-challenge-nonce|{ip ?? ""}|{day.ToString(CultureInfo.InvariantCulture)}";

    public static string TokenMessage(string? ip, long exp) => $"camada-challenge-token|{ip ?? ""}|{exp.ToString(CultureInfo.InvariantCulture)}";

    public static (long Exp, string Mac)? SplitToken(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }
        var dot = value.IndexOf('.');
        if (dot <= 0)
        {
            return null;
        }
        if (!long.TryParse(value[..dot], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var exp))
        {
            return null;
        }
        var mac = value[(dot + 1)..];
        return mac.Length > 0 ? (exp, mac) : null;
    }

    /// <summary>Constant-time for equal-length strings; length itself is not a secret here.</summary>
    public static bool SafeEqual(string a, string b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    /// <summary>True when the hex digest starts with `bits` zero bits.</summary>
    public static bool PowOk(string hexDigest, int bits = PowBits)
    {
        int nibbles = bits >> 2, rest = bits & 3;
        if (hexDigest.Length < nibbles + (rest != 0 ? 1 : 0))
        {
            return false;
        }
        for (var i = 0; i < nibbles; i++)
        {
            if (hexDigest[i] != '0')
            {
                return false;
            }
        }
        if (rest == 0)
        {
            return true;
        }
        if (!int.TryParse(hexDigest.AsSpan(nibbles, 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v))
        {
            return false;
        }
        return (v >> (4 - rest)) == 0;
    }

    public static bool SolutionShapeOk(string? solution) => !string.IsNullOrEmpty(solution) && solution.Length <= MaxSolution;

    public static string Cookie(string value, bool secure) =>
        $"{ChallengeCookie}={value}; Path=/; Max-Age={ChallengeTtlMs / 1000}; HttpOnly; SameSite=Lax{(secure ? "; Secure" : "")}";

    /// <summary>Only a printable-ASCII same-site absolute path survives: never an absolute URL, a
    /// protocol-relative '//host' redirect, a control character, or something absurdly long.</summary>
    public static string SafeReturnTo(string? raw)
    {
        if (string.IsNullOrEmpty(raw) || raw.Length > MaxReturnTo)
        {
            return "/";
        }
        if (raw[0] != '/' || (raw.Length > 1 && (raw[1] == '/' || raw[1] == '\\')))
        {
            return "/";
        }
        foreach (var c in raw)
        {
            if (c < 0x21 || c > 0x7E)
            {
                return "/";
            }
        }
        return raw;
    }

    /// <summary>A challenge page is only worth serving to a top-level HTML navigation (contract §D2).</summary>
    public static bool WantsHtml(string? accept, string? secFetchDest)
    {
        if (string.IsNullOrEmpty(accept) || !accept.Contains("text/html", StringComparison.Ordinal))
        {
            return false;
        }
        return string.IsNullOrEmpty(secFetchDest) || secFetchDest == "document";
    }

    public static string EscapeAttr(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");

    /// <summary>Safe to drop inside an inline &lt;script&gt;: the JSON string literal json.dumps would write
    /// (ASCII only, lower-case \uXXXX), with `&lt;` escaped so no value can close the element early.</summary>
    public static string EscapeScript(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '<': sb.Append("\\u003c"); break;
                default:
                    if (c < 0x20 || c > 0x7E)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    /// <summary>application/x-www-form-urlencoded, last value wins. Never throws on junk.</summary>
    public static Dictionary<string, string> ParseFormBody(string body)
    {
        var outMap = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in body.Split('&'))
        {
            if (pair.Length == 0)
            {
                continue;
            }
            var eq = pair.IndexOf('=');
            var k = eq == -1 ? pair : pair[..eq];
            var v = eq == -1 ? "" : pair[(eq + 1)..];
            outMap[Unquote(k)] = Unquote(v);
        }
        return outMap;
    }

    private static string Unquote(string s)
    {
        try
        {
            return Uri.UnescapeDataString(s.Replace('+', ' '));
        }
        catch
        {
            return s;
        }
    }
}

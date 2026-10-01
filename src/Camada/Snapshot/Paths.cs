// Path canonicalisation (contracts §D3 "Path matching"), ported byte for byte from edge-analyst
// src/blocklist.js canonPath / pathForms / pathHit / pathPred. A path rule must catch every spelling a
// router sends to the same handler, so both sides of a comparison are canonicalised: query cut at ? or #;
// %XX decoded when it is printable ASCII other than / and % (so %2F never becomes a separator and
// decoding stays one pass); every other byte, raw non-ASCII included, written as lower-case %xx of its
// UTF-8; ASCII lower-cased (ASP.NET Core and Express route case-insensitively); each segment cut at its
// first ; (servlet path parameters); empty segments dropped (// and the trailing slash); and . / ..
// resolved — the `full` form. The `lit` form skips that last step, for a router that sends /locked/../x
// to the /locked handler unresolved. A deny fires when the raw path, lit or full matches; an exemption
// (allow side, skip rule) needs lit AND full. Path regexes are case-insensitive.
using System.Text;
using System.Text.RegularExpressions;

namespace Camada.Snapshot;

public static class Paths
{
    private const string Hex = "0123456789abcdef";

    // already canonical: the common case skips the byte walk
    private static readonly Regex Canonical = new(@"^(?:/(?!\.\.?(?:/|$))[a-z0-9\-._~!$&'()*+,=:@]+)+$", RegexOptions.CultureInvariant);

    private static int HexVal(byte c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

    private static string StripQuery(string? raw)
    {
        var p = string.IsNullOrEmpty(raw) ? "/" : raw;
        var q = p.IndexOfAny(['?', '#']);
        return q == -1 ? p : p[..q];
    }

    private static bool IsCanonical(string p) => p == "/" || Canonical.IsMatch(p);

    public static string Canon(string? raw, bool dots = true)
    {
        var p = StripQuery(raw);
        if (IsCanonical(p))
        {
            return p;
        }
        var b = Encoding.UTF8.GetBytes(p);
        var s = new StringBuilder(b.Length + 8);
        for (var i = 0; i < b.Length; i++)
        {
            int c = b[i];
            if (c == '%' && i + 2 < b.Length && HexVal(b[i + 1]) >= 0 && HexVal(b[i + 2]) >= 0)
            {
                c = HexVal(b[i + 1]) * 16 + HexVal(b[i + 2]);
                i += 2;
                if (c == '/')
                {
                    s.Append("%2f");
                    continue;
                }
            }
            if (c < 0x21 || c > 0x7e || c == '%')
            {
                s.Append('%').Append(Hex[c >> 4]).Append(Hex[c & 15]);
                continue;
            }
            s.Append((char)(c >= 'A' && c <= 'Z' ? c + 32 : c));
        }
        var segs = new List<string>();
        foreach (var seg0 in s.ToString().Split('/'))
        {
            var k = seg0.IndexOf(';');
            var seg = k == -1 ? seg0 : seg0[..k];
            if (seg.Length == 0 || (dots && seg == "."))
            {
                continue;
            }
            if (dots && seg == "..")
            {
                if (segs.Count > 0)
                {
                    segs.RemoveAt(segs.Count - 1);
                }
                continue;
            }
            segs.Add(seg);
        }
        return "/" + string.Join('/', segs);
    }

    /// <summary>[raw (query cut), lit, full] for one request path.</summary>
    public static string[] Forms(string? raw)
    {
        var p = StripQuery(raw);
        return IsCanonical(p) ? [p, p, p] : [p, Canon(p, false), Canon(p, true)];
    }

    private static string Dir(string p) => p.EndsWith('/') ? p : p + "/";

    /// <summary>A prefix entry or a starts_with value ending in / -> its canonical directory key ('/' stays '/').</summary>
    public static string DirKey(string v) => Dir(Canon(v));

    /// <summary>Walks '/' boundaries: /a/b tries /, /a/, /a/b/.</summary>
    public static bool Prefixed(HashSet<string> prefixes, string path)
    {
        var d = Dir(path);
        for (var i = 0; i != -1; i = d.IndexOf('/', i + 1))
        {
            if (prefixes.Contains(d[..(i + 1)]))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Does `pred` hold for this request's path? deny (block/challenge/warn) = any spelling;
    /// exemption (allow/skip) = both canonical forms.</summary>
    public static bool Hit(Func<string, bool> pred, string[] forms, bool deny) =>
        deny ? pred(forms[0]) || pred(forms[1]) || pred(forms[2]) : pred(forms[1]) && pred(forms[2]);

    /// <summary>One path condition -> a predicate over a single path form.</summary>
    public static Func<string, bool> Pred(string op, IReadOnlyList<string> values)
    {
        if (op == "matches")
        {
            var rx = Parser.CompileRegex(values[0], ignoreCase: true);
            return p => rx != null && Parser.Search(rx, p);
        }
        if (op == "starts_with")
        {
            var v = values[0];
            var key = v.EndsWith('/') ? DirKey(v) : Canon(v);
            return p => Dir(p).StartsWith(key, StringComparison.Ordinal);
        }
        var set = new HashSet<string>(values.Select(v => Canon(v)), StringComparer.Ordinal);
        return set.Contains;
    }
}

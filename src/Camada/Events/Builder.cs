// Wire-event builder: reproduces the collector's record() (edge-analyst
// workers/collector/edge-collector.js) from a normalized request, so events are comparable
// across taps. HDRS bit order is pinned by the shared fixture (hdrs.json) — never reorder.
using System.Text.RegularExpressions;

namespace Camada.Events;

public sealed record RequestInfo(
    string Method,
    string Host,
    string Path,
    string Query,                                        // includes the leading '?', or empty
    IList<KeyValuePair<string, string>>? Headers,        // in the order the host gives them
    string? Ip,                                          // already resolved via trusted-proxy config
    string? HttpVersion);                                // e.g. '1.1'

public static partial class Builder
{
    public static readonly string[] Hdrs =
    {
        "accept", "accept-language", "accept-encoding", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
        "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "dnt",
        "cache-control", "pragma", "referer", "origin", "cookie", "authorization", "x-requested-with", "content-type",
        "via", "x-forwarded-for", "priority", "sec-purpose", "save-data", "te", "if-modified-since", "if-none-match",
    };

    private static readonly Dictionary<string, int> HdrBit = Hdrs.Select((n, i) => (n, i)).ToDictionary(p => p.n, p => 1 << p.i, StringComparer.Ordinal);

    // A schemeless header (`Authorization: <raw token>`) has no safe prefix: the first "word" IS
    // the credential. Only a real auth-scheme token followed by a space ever ships.
    [GeneratedRegex("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,16}$", RegexOptions.CultureInvariant)]
    private static partial Regex SchemeRe();

    public static string? AuthScheme(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }
        var sp = value.IndexOf(' ');
        if (sp <= 0)
        {
            return null;
        }
        var scheme = value[..sp];
        return SchemeRe().IsMatch(scheme) ? scheme : null;
    }

    public static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>The mutable wire event; the caller fills st/dur on response-finish before enqueueing.</summary>
    public static Dictionary<string, object?> BuildWireEvent(RequestInfo r, string tap, string rid, string? sid = null, bool newSession = false, string? ja4 = null)
    {
        int mask = 0, hn = 0, hb = 0;
        var cookie = "";
        var names = new List<string>();
        var first = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, value) in r.Headers ?? Array.Empty<KeyValuePair<string, string>>())
        {
            var k = name.ToLowerInvariant();
            hn++;
            hb += name.Length + value.Length;
            names.Add(k);
            first.TryAdd(k, value);
            mask |= HdrBit.GetValueOrDefault(k, 0);
            if (k == "cookie")
            {
                cookie = cookie.Length > 0 ? cookie + "; " + value : value;
            }
        }
        string? H(string n) => first.GetValueOrDefault(n);
        var query = r.Query ?? "";
        var qn = query.Length > 1 ? query[1..].Split('&').Count(p => p.Length > 0) : 0;
        var hord = string.Join(",", names);
        var ev = new Dictionary<string, object?>
        {
            ["tap"] = tap,
            ["rid"] = rid,
            ["sid"] = sid,
            ["ns"] = newSession ? 1 : 0,
            ["ts"] = NowMs(),
            ["ip"] = r.Ip,
            ["proto"] = string.IsNullOrEmpty(r.HttpVersion) ? null : "HTTP/" + r.HttpVersion,
            ["m"] = r.Method,
            ["h"] = r.Host,
            ["p"] = r.Path,
            ["q"] = Cap(Redact.ScrubQuery(query), 512),
            ["qn"] = qn,
            ["ct"] = H("content-type"),
            ["cl"] = H("content-length"),
            ["ua"] = H("user-agent"),
            ["chua"] = H("sec-ch-ua"),
            ["chmob"] = H("sec-ch-ua-mobile"),
            ["chplat"] = H("sec-ch-ua-platform"),
            ["acc"] = H("accept"),
            ["lang"] = H("accept-language"),
            ["fs"] = H("sec-fetch-site"),
            ["fm"] = H("sec-fetch-mode"),
            ["fd"] = H("sec-fetch-dest"),
            ["fu"] = H("sec-fetch-user"),
            ["ref"] = H("referer"),
            ["org"] = H("origin"),
            ["xrw"] = H("x-requested-with"),
            ["auth"] = AuthScheme(H("authorization")),   // scheme only, never the credential
            ["hm"] = mask,
            ["hn"] = hn,
            ["hb"] = hb,
            ["ck"] = cookie.Length > 0 ? cookie.Split(';').Length : 0,
            ["hord"] = Cap(hord, 2048),   // header order as this host reports it
        };
        if (!string.IsNullOrEmpty(ja4))
        {
            ev["ja4"] = ja4;
        }
        ev["st"] = null;
        ev["dur"] = null;   // 'dur': the collector wire already claims 'lat' for latitude
        return ev;
    }

    private static string Cap(string s, int n) => s.Length > n ? s[..n] : s;
}

// Matcher: sub-millisecond checks over a parsed Snapshot, ported from @camada/core
// src/snapshot/match.ts (itself from edge-analyst src/blocklist.js). Matching is fully
// synchronous and allocation-light. The original's per-instance scratch request is not ported:
// a JS isolate runs one match() at a time, but here one Matcher serves every request thread, so
// the rule loop reads a RuleRequest built per call.
//
// Outcome order is contract (contracts §D3, fixtures pin it): the tenant's ordered custom rules
// first (first match wins, the order IS the precedence), then allow -> block -> challenge.
// Within each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path.
// At the SDK position only ip, path, ua and the request headers are usually known;
// asn/country/tlsx entries and conditions then simply never match — that is the documented,
// honest enforcement scope (fail open, never guess).
namespace Camada.Snapshot;

public sealed record MatchInput
{
    public string? Ip { get; init; }
    public long? Asn { get; init; }
    public string? Country { get; init; }
    public string? Tlsx { get; init; }
    public string? Path { get; init; }
    public string? Ua { get; init; }                        // v5 rules read it; the three sides never do
    public Func<string, string?>? Header { get; init; }     // v5 header conditions read it, always with a lower-cased name
}

public sealed record MatchResult(
    bool Block = false,
    bool Challenge = false,
    bool Allowed = false,           // true for skip (which absorbed the old allow) and for the allow side
    bool Warn = false,
    string? Action = null,          // the action of the rule that decided, null when a side did
    string? Rule = null,            // the rule id, present only when Reason is 'rule'
    string? Reason = null,          // ip4 | ip6 | asn | country | tls | path | rule | cold
    string? Version = null);

public sealed class Matcher
{
    public Snapshot Snap { get; }

    public Matcher(Snapshot snap) => Snap = snap;

    public static string CleanPath(string? raw)
    {
        var p = string.IsNullOrEmpty(raw) ? "/" : raw;
        var q = p.IndexOf('?');
        return q == -1 ? p : p[..q];
    }

    /// <summary>Walks every '/'-terminated ancestor of `path`, the way the block side does.</summary>
    private static bool PrefixHit(HashSet<string> prefixes, string path)
    {
        var i = path.IndexOf('/', 1);
        while (i != -1)
        {
            if (prefixes.Contains(path[..(i + 1)]))
            {
                return true;
            }
            i = path.IndexOf('/', i + 1);
        }
        return false;
    }

    /// <summary>A rule decided this request (§D3): at most one of Allowed / Block / Challenge / Warn is
    /// true, `Reason` is 'rule', and `Rule` names the id the adapters stamp on the event.</summary>
    private static MatchResult RuleResult(CompiledRule rule, string version)
    {
        var a = rule.Action;
        return new MatchResult(
            Block: a == "block", Challenge: a == "challenge", Allowed: a == "skip", Warn: a == "warn",
            Action: a, Rule: rule.Id, Reason: "rule", Version: version);
    }

    private bool Blocked4(long n)
    {
        var s = Snap;
        var b = n >> 8;
        if (((s.Bm4[(int)(b >> 5)] >> (int)(b & 31)) & 1) == 0)
        {
            return false;
        }
        var hi = (int)(n >> 16);
        long left = s.Idx4[hi], right = (long)s.Idx4[hi + 1] - 1;
        if (left > 0)
        {
            left--;
        }
        if (right < left)
        {
            return false;
        }
        var s4 = s.S4.Span;
        while (left < right)
        {
            var m = (left + right + 1) >> 1;
            if (s4[(int)m] <= n)
            {
                left = m;
            }
            else
            {
                right = m - 1;
            }
        }
        return s4[(int)left] <= n && n <= s.E4[(int)left];
    }

    private bool Blocked6(uint[] w)
    {
        var s = Snap;
        var b = w[0] >> 8;
        if (((s.Bm6[(int)(b >> 5)] >> (int)(b & 31)) & 1) == 0)
        {
            return false;
        }
        int left = 0, right = s.N6 - 1;
        if (right < 0)
        {
            return false;
        }
        var s6 = s.S6.Span;
        while (left < right)
        {
            var m = (left + right + 1) >> 1;
            if (Parser.CmpWords(s6, m * 4, w) <= 0)
            {
                left = m;
            }
            else
            {
                right = m - 1;
            }
        }
        var o = left * 4;
        return Parser.CmpWords(s6, o, w) <= 0 && Parser.CmpWords(s.E6.Span, o, w) >= 0;
    }

    private bool BlockedAsn(long asn)
    {
        var s = Snap;
        if (asn < 0)
        {
            return false;
        }
        if (asn < 4194304)
        {
            return ((s.AsnBm[(int)(asn >> 5)] >> (int)(asn & 31)) & 1) != 0;
        }
        var extra = s.AsnExtra.Span;
        int left = 0, right = extra.Length - 1;
        while (left <= right)
        {
            var m = (left + right) >> 1;
            var v = extra[m];
            if (v == asn)
            {
                return true;
            }
            if (v < asn)
            {
                left = m + 1;
            }
            else
            {
                right = m - 1;
            }
        }
        return false;
    }

    private bool BlockedPath(string path)
    {
        var s = Snap;
        if (s.PathsExact.Contains(path))
        {
            return true;
        }
        if (s.PathsPrefix.Count > 0 && PrefixHit(s.PathsPrefix, path))
        {
            return true;
        }
        foreach (var rx in s.PathsRegex)
        {
            if (Parser.Search(rx, path))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>The block side: v3 sections plus the top-level meta.</summary>
    private string? BlockSide(MatchInput i, long n4, uint[]? w)
    {
        var s = Snap;
        if (n4 >= 0 && Blocked4(n4))
        {
            return "ip4";
        }
        if (w != null && Blocked6(w))
        {
            return "ip6";
        }
        if (i.Asn is { } asn && BlockedAsn(asn))
        {
            return "asn";
        }
        if (!string.IsNullOrEmpty(i.Country) && s.Country.Count > 0 && s.Country.Contains(i.Country))
        {
            return "country";
        }
        if (!string.IsNullOrEmpty(i.Tlsx) && s.Tls.Contains(i.Tlsx))
        {
            return "tls";
        }
        if ((s.PathsExact.Count > 0 || s.PathsPrefix.Count > 0 || s.PathsRegex.Count > 0) && BlockedPath(CleanPath(i.Path)))
        {
            return "path";
        }
        return null;
    }

    /// <summary>A v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key.</summary>
    private static string? Side(RangeSet st, MatchInput i, long n4, uint[]? w)
    {
        if (st.Empty)
        {
            return null;   // the common v3 snapshot
        }
        if (n4 >= 0 && Parser.InRange4(st.R4, n4))
        {
            return "ip4";
        }
        if (w != null && Parser.InRange6(st.R6, st.N6, w))
        {
            return "ip6";
        }
        if (i.Asn is { } asn && st.Asn.Contains(asn))
        {
            return "asn";
        }
        if (!string.IsNullOrEmpty(i.Country) && st.Country.Contains(i.Country))
        {
            return "country";
        }
        if (st.PathsExact.Count > 0 || st.PathsPrefix.Count > 0)
        {
            var p = CleanPath(i.Path);
            if (st.PathsExact.Contains(p))
            {
                return "path";
            }
            if (st.PathsPrefix.Count > 0 && PrefixHit(st.PathsPrefix, p))
            {
                return "path";
            }
        }
        return null;
    }

    public MatchResult Match(MatchInput i)
    {
        var s = Snap;
        var ip = i.Ip ?? "";
        long n4 = -1;
        uint[]? w = null;
        if (ip.Length > 0)
        {
            if (!ip.Contains(':'))
            {
                n4 = IpParse.ParseIp4(ip);
            }
            else
            {
                w = IpParse.ParseIp6(ip);
            }
        }
        if (s.Rules.Count > 0)
        {
            var r = new RuleRequest { N4 = n4, Ip6 = w, Asn = i.Asn, Country = i.Country, Tlsx = i.Tlsx, Path = CleanPath(i.Path), Ua = i.Ua, Header = i.Header };
            foreach (var rule in s.Rules)   // the order IS the precedence (§A4): first match wins
            {
                var all = true;
                foreach (var cond in rule.Conds)
                {
                    if (!cond(r))
                    {
                        all = false;
                        break;
                    }
                }
                if (all)
                {
                    return RuleResult(rule, s.Version);
                }
            }
        }
        var reason = Side(s.Allow, i, n4, w);
        if (reason != null)
        {
            return new MatchResult(Allowed: true, Reason: reason, Version: s.Version);
        }
        reason = BlockSide(i, n4, w);
        if (reason != null)
        {
            return new MatchResult(Block: true, Reason: reason, Version: s.Version);
        }
        reason = Side(s.Challenge, i, n4, w);
        if (reason != null)
        {
            return new MatchResult(Challenge: true, Reason: reason, Version: s.Version);
        }
        return new MatchResult(Version: s.Version);
    }
}

// BLK snapshot parser (v3, v4, v5), ported from @camada/core src/snapshot/parse.ts, itself a
// port of edge-analyst src/blocklist.js load() (the reference implementation).
//
// Container: sectioned little-endian uint32 —
//   [0] magic 0x424c4b3<version>   [1] section count K
//   K x [type, offset(words), length(words)]   then the sections.
// Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
//        8 ASN_BM  9 ASN_EXTRA.
// v4 (contracts §A3) adds two side lists as INTERLEAVED range pairs:
//        10 ALLOW_V4  11 ALLOW_V6  12 CHALLENGE_V4  13 CHALLENGE_V6
//   *_V4: [start, end, …] (2 words per range, sorted by start)
//   *_V6: [s0,s1,s2,s3, e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start)
// v5 (contracts §D3) adds the tenant's ordered custom rules, which run BEFORE the three sides:
//        14 RULE_V4  15 RULE_V6   — repeated, word 0 = the rule's index into meta.rules, then range
//   pairs exactly as 10/11. One 14 + one 15 per `ip` condition, in condition order (an empty half
//   still ships its index word), so a rule with two ip conditions reads two pairs.
// Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
//                            allow?: side, challenge?: side, rules?: [] } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
// The version byte is advisory: sections 10-15 are read whenever they are present.
//
// A Uint32Array is a MemoryMarshal.Cast over the frame's bytes: zero-copy, native-endian, so the
// parser refuses a big-endian platform rather than match garbage (Python's port does the same).
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Camada.Snapshot;

public sealed class SnapshotFormatException : Exception
{
    public SnapshotFormatException(string message) : base(message)
    {
    }
}

/// <summary>A uint32 view over a byte slice: the port of a Uint32Array, allocation-free.</summary>
public readonly struct U32
{
    private readonly ReadOnlyMemory<byte> _bytes;

    public U32(ReadOnlyMemory<byte> bytes) => _bytes = bytes[..(bytes.Length - bytes.Length % 4)];   // a trailing partial word is dropped, as the Uint32Array view does

    public static readonly U32 Empty = new(ReadOnlyMemory<byte>.Empty);

    public int Length => _bytes.Length >> 2;

    public ReadOnlySpan<uint> Span => MemoryMarshal.Cast<byte, uint>(_bytes.Span);

    public uint this[int i] => Span[i];

    public U32 Slice(int words) => new(_bytes[(words * 4)..]);

    public static U32 Zeros(int words) => new(new byte[words * 4]);
}

/// <summary>A v4 side list. `Empty` short-circuits the matcher on the (common) v3 snapshot.</summary>
public sealed class RangeSet
{
    public required U32 R4 { get; init; }           // interleaved [start, end]
    public required U32 R6 { get; init; }           // interleaved [4-word start, 4-word end]
    public required int N6 { get; init; }           // range count in R6
    public required HashSet<long> Asn { get; init; }
    public required HashSet<string> Country { get; init; }
    public required HashSet<string> PathsExact { get; init; }
    public required HashSet<string> PathsPrefix { get; init; }
    public required bool Empty { get; init; }
}

/// <summary>The request a compiled condition reads. `Ip6` is the parsed address words, or null.</summary>
public sealed class RuleRequest
{
    public long N4 { get; init; } = -1;                  // IPv4 as uint32, or -1 when this request has no IPv4 address
    public uint[]? Ip6 { get; init; }
    public long? Asn { get; init; }
    public string? Country { get; init; }
    public string? Tlsx { get; init; }
    public string Path { get; init; } = "/";             // already query-stripped
    public string? Ua { get; init; }
    public Func<string, string?>? Header { get; init; }  // called with an already lower-cased name; absent where the tap cannot read headers
}

public delegate bool RuleCond(RuleRequest r);

public sealed record CompiledRule(string Id, string Action, IReadOnlyList<RuleCond> Conds);

public sealed class Snapshot
{
    public required string Version { get; init; }
    public required int Format { get; init; }            // what the container's version byte claimed
    public required U32 S4 { get; init; }
    public required U32 E4 { get; init; }
    public required U32 Idx4 { get; init; }
    public required U32 Bm4 { get; init; }
    public required U32 S6 { get; init; }
    public required U32 E6 { get; init; }
    public required int N6 { get; init; }
    public required U32 Bm6 { get; init; }
    public required U32 AsnBm { get; init; }
    public required U32 AsnExtra { get; init; }
    public required HashSet<string> Country { get; init; }
    public required HashSet<string> Tls { get; init; }
    public required HashSet<string> PathsExact { get; init; }
    public required HashSet<string> PathsPrefix { get; init; }
    public required IReadOnlyList<Regex> PathsRegex { get; init; }
    public required RangeSet Allow { get; init; }
    public required RangeSet Challenge { get; init; }
    public required IReadOnlyList<CompiledRule> Rules { get; init; }   // v5 only; empty on v3/v4, and the matcher then skips them
}

public static class Parser
{
    private static readonly Dictionary<uint, int> Formats = new() { [0x424C4B33] = 3, [0x424C4B34] = 4, [0x424C4B35] = 5 };
    private static readonly HashSet<string> Actions = new() { "skip", "block", "challenge", "warn" };
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(50);

    private static U32 Words(ReadOnlyMemory<byte> binary)
    {
        if (!BitConverter.IsLittleEndian)
        {
            throw new PlatformNotSupportedException("camada: big-endian platforms are not supported");
        }
        return new U32(binary);
    }

    private static HashSet<string> Strings(JsonElement meta, string name)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (meta.ValueKind == JsonValueKind.Object && meta.TryGetProperty(name, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in arr.EnumerateArray())
            {
                set.Add(Text(e));
            }
        }
        return set;
    }

    private static HashSet<long> Longs(JsonElement meta, string name)
    {
        var set = new HashSet<long>();
        if (meta.ValueKind == JsonValueKind.Object && meta.TryGetProperty(name, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in arr.EnumerateArray())
            {
                if (long.TryParse(Text(e), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
                {
                    set.Add(n);
                }
            }
        }
        return set;
    }

    /// <summary>A JSON scalar as the string the reference's String(x) gives: numbers keep their JSON spelling.</summary>
    private static string Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString()! : e.GetRawText();

    private static RangeSet MakeRangeSet(U32 r4, U32 r6, JsonElement m)
    {
        var asn = Longs(m, "asn");
        var country = Strings(m, "country");
        var exact = Strings(m, "pathsExact");
        var prefix = Strings(m, "pathsPrefix");
        var empty = r4.Length == 0 && r6.Length == 0 && asn.Count == 0 && country.Count == 0 && exact.Count == 0 && prefix.Count == 0;
        return new RangeSet { R4 = r4, R6 = r6, N6 = r6.Length >> 3, Asn = asn, Country = country, PathsExact = exact, PathsPrefix = prefix, Empty = empty };
    }

    /// <summary>Binary search over interleaved [start, end] uint32 pairs sorted by start.</summary>
    public static bool InRange4(U32 r, long n)
    {
        var s = r.Span;
        int lo = 0, hi = (s.Length >> 1) - 1;
        if (hi < 0)
        {
            return false;
        }
        while (lo < hi)
        {
            var m = (lo + hi + 1) >> 1;
            if (s[m * 2] <= n)
            {
                lo = m;
            }
            else
            {
                hi = m - 1;
            }
        }
        return s[lo * 2] <= n && n <= s[lo * 2 + 1];
    }

    /// <summary>Compares the 4 words at a[o..o+3] against the address words.</summary>
    internal static int CmpWords(ReadOnlySpan<uint> a, int o, uint[] w)
    {
        for (var k = 0; k < 4; k++)
        {
            uint x = a[o + k], y = w[k];
            if (x != y)
            {
                return x < y ? -1 : 1;
            }
        }
        return 0;
    }

    /// <summary>Binary search over an interleaved [4-word start, 4-word end] side section.</summary>
    public static bool InRange6(U32 r, int n, uint[] w)
    {
        if (n < 1)
        {
            return false;
        }
        var s = r.Span;
        int lo = 0, hi = n - 1;
        while (lo < hi)
        {
            var m = (lo + hi + 1) >> 1;
            if (CmpWords(s, m * 8, w) <= 0)
            {
                lo = m;
            }
            else
            {
                hi = m - 1;
            }
        }
        var o = lo * 8;
        return CmpWords(s, o, w) <= 0 && CmpWords(s, o + 4, w) >= 0;
    }

    /// <summary>A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
    /// authored as JS regexes (the analyst validates them with `new RegExp`), so ECMAScript mode is tried
    /// first — it keeps \d \w \b ASCII and reads `[^]`, `\cX` and named groups as JS does — and a spelling
    /// it refuses is retried on the default engine after JsToDotNet. Every match runs under a timeout.</summary>
    public static Regex? CompileRegex(string pattern)
    {
        try
        {
            return new Regex(pattern, RegexOptions.ECMAScript | RegexOptions.CultureInvariant, MatchTimeout);
        }
        catch (ArgumentException)
        {
            // fall through: the default engine, with the JS-only spellings translated
        }
        try
        {
            return new Regex(JsToDotNet(pattern), RegexOptions.CultureInvariant, MatchTimeout);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>The one JS spelling the default engine refuses: `[^]` (any char) becomes `[\s\S]`.
    /// Named groups and `\cX` are native; anything else the engine rejects still fails open.</summary>
    public static string JsToDotNet(string pattern)
    {
        var sb = new System.Text.StringBuilder(pattern.Length + 8);
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var ch = pattern[i];
            if (ch == '\\' && i + 1 < pattern.Length)
            {
                sb.Append(ch).Append(pattern[i + 1]);
                i++;
                continue;
            }
            if (inClass)
            {
                inClass = ch != ']';
            }
            else if (ch == '[')
            {
                if (string.CompareOrdinal(pattern, i, "[^]", 0, 3) == 0)
                {
                    sb.Append("[\\s\\S]");
                    i += 2;
                    continue;
                }
                inClass = true;
            }
            sb.Append(ch);
        }
        return sb.ToString();
    }

    /// <summary>A guarded IsMatch: a timeout (catastrophic backtracking on hostile input) is no match, never a throw.</summary>
    internal static bool Search(Regex rx, string input)
    {
        try
        {
            return rx.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    // ---------- custom rules (v5) ----------

    /// <summary>The string one condition reads, or null when this request cannot answer the field.
    /// `header` is not here: it needs the condition's own name, so CompileCond builds its reader.</summary>
    private static string? FieldValue(string f, RuleRequest r) => f switch
    {
        "asn" => r.Asn?.ToString(CultureInfo.InvariantCulture),
        "country" => string.IsNullOrEmpty(r.Country) ? null : r.Country,
        "tlsx" => string.IsNullOrEmpty(r.Tlsx) ? null : r.Tlsx,
        "path" => r.Path,
        "ua" => string.IsNullOrEmpty(r.Ua) ? null : r.Ua,
        _ => null,   // an entity-plane field (bot.verified, rule): never true here
    };

    private static string Prop(JsonElement c, string name) =>
        c.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null && v.ValueKind != JsonValueKind.Undefined ? Text(v) : "";

    /// <summary>One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip
    /// condition, in condition order, so an ip condition consumes the next one.</summary>
    private static RuleCond CompileCond(JsonElement c, Queue<(U32 V4, U32 V6)> sets)
    {
        var f = Prop(c, "f");
        var op = Prop(c, "op");
        var negate = op is "is_not" or "not_in";
        // A header condition reads the request through the caller's getter. The name is lower-cased
        // once, here; a tap that cannot read headers (no getter) and a header the request does not
        // carry are both null, and null is false for every op — the rule simply does not fire (fail
        // open, §A4). The getter is app code: one that throws is read as "no header" rather than
        // allowed to take the whole Match() down.
        Func<RuleRequest, string?> read;
        if (f == "header")
        {
            var hname = Prop(c, "name").ToLowerInvariant();
            read = r =>
            {
                if (hname.Length == 0 || r.Header == null)
                {
                    return null;
                }
                try
                {
                    return r.Header(hname);
                }
                catch
                {
                    return null;
                }
            };
        }
        else
        {
            read = r => FieldValue(f, r);
        }

        if (f == "ip")
        {
            var (p4, p6) = sets.Count > 0 ? sets.Dequeue() : (U32.Empty, U32.Empty);
            var n6 = p6.Length >> 3;
            return r =>
            {
                if (r.N4 < 0 && r.Ip6 == null)
                {
                    return false;   // no address: false for every op, negatives included
                }
                var hit = (r.N4 >= 0 && InRange4(p4, r.N4)) || (r.Ip6 != null && InRange6(p6, n6, r.Ip6));
                return negate ? !hit : hit;
            };
        }
        var values = new List<string>();
        if (c.TryGetProperty("v", out var raw) && raw.ValueKind == JsonValueKind.Array)
        {
            values.AddRange(raw.EnumerateArray().Select(Text));
        }
        else
        {
            values.Add(Prop(c, "v"));
        }
        if (op == "matches")
        {
            var rx = CompileRegex(values[0]);
            return r =>
            {
                var v = read(r);
                return v != null && rx != null && Search(rx, v);
            };
        }
        if (op == "contains")
        {
            var needle = values[0];
            return r => read(r) is { } v && v.Contains(needle, StringComparison.Ordinal);
        }
        if (op == "starts_with")
        {
            var prefix = values[0];
            return r => read(r) is { } v && v.StartsWith(prefix, StringComparison.Ordinal);
        }
        var members = new HashSet<string>(values, StringComparer.Ordinal);   // is | is_not | is_in | not_in
        return r =>
        {
            var v = read(r);
            if (v == null)
            {
                return false;
            }
            return negate ? !members.Contains(v) : members.Contains(v);
        };
    }

    /// <summary>meta.rules + the repeated 14/15 sections -> predicates, in evaluation order. A rule this SDK
    /// cannot compile (unknown action, no conditions) is dropped rather than guessed at.</summary>
    private static List<CompiledRule> CompileRules(JsonElement meta, List<U32> v4s, List<U32> v6s)
    {
        var outRules = new List<CompiledRule>();
        if (meta.ValueKind != JsonValueKind.Object || !meta.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array)
        {
            return outRules;
        }
        var i = -1;
        foreach (var r in rules.EnumerateArray())
        {
            i++;
            if (r.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var action = Prop(r, "action");
            if (!Actions.Contains(action))
            {
                continue;   // an action this SDK does not know: ignore the rule rather than guess
            }
            var v4 = v4s.Where(s => s.Length > 0 && s[0] == i).ToList();
            var v6 = v6s.Where(s => s.Length > 0 && s[0] == i).ToList();
            var sets = new Queue<(U32, U32)>();
            for (var k = 0; k < Math.Max(v4.Count, v6.Count); k++)
            {
                sets.Enqueue((k < v4.Count ? v4[k].Slice(1) : U32.Empty, k < v6.Count ? v6[k].Slice(1) : U32.Empty));
            }
            var conds = new List<RuleCond>();
            try
            {
                if (r.TryGetProperty("conds", out var cs) && cs.ValueKind == JsonValueKind.Array)
                {
                    foreach (var c in cs.EnumerateArray())
                    {
                        conds.Add(CompileCond(c, sets));
                    }
                }
            }
            catch
            {
                continue;   // a malformed rule is dropped, never enforced
            }
            if (conds.Count > 0)
            {
                outRules.Add(new CompiledRule(Prop(r, "id"), action, conds));   // a rule with no conditions would match everything
            }
        }
        return outRules;
    }

    /// <summary>Parses a BLK container + meta into a Snapshot. Throws on a malformed container — callers
    /// keep the previous snapshot, exactly like the edge collector does.</summary>
    public static Snapshot ParseSnapshot(ReadOnlyMemory<byte> binary, JsonElement meta)
    {
        var u = Words(binary);
        if (u.Length < 2 || !Formats.TryGetValue(u[0], out var fmt))
        {
            throw new SnapshotFormatException("camada: not a BLK3 snapshot");
        }
        var count = u[1];
        var sec = new Dictionary<uint, U32>();
        var rule4 = new List<U32>();
        var rule6 = new List<U32>();
        if ((long)u.Length < 2 + (long)count * 3)
        {
            throw new SnapshotFormatException("camada: truncated BLK3 header");
        }
        for (var i = 0; i < count; i++)
        {
            uint t = u[2 + i * 3], off = u[3 + i * 3], ln = u[4 + i * 3];
            if ((long)off + ln > u.Length)
            {
                throw new SnapshotFormatException("camada: truncated BLK3 section");
            }
            var s = new U32(binary.Slice((int)off * 4, (int)ln * 4));
            if (t == 14)
            {
                rule4.Add(s);   // repeated, one per ip condition: kept in container order
            }
            else if (t == 15)
            {
                rule6.Add(s);
            }
            else
            {
                sec[t] = s;
            }
        }
        var s6 = Sec(sec, 5);
        var version = meta.ValueKind == JsonValueKind.Object && meta.TryGetProperty("version", out var ver) ? Text(ver) : "";
        return new Snapshot
        {
            Version = version,
            Format = fmt,
            S4 = Sec(sec, 1),
            E4 = Sec(sec, 2),
            Idx4 = SecOr(sec, 3, 65537),
            Bm4 = SecOr(sec, 4, 524288),
            S6 = s6,
            E6 = Sec(sec, 6),
            N6 = s6.Length / 4,
            Bm6 = SecOr(sec, 7, 524288),
            AsnBm = SecOr(sec, 8, 131072),
            AsnExtra = Sec(sec, 9),
            Country = Strings(meta, "country"),
            Tls = Strings(meta, "tls"),
            PathsExact = Strings(meta, "pathsExact"),
            PathsPrefix = Strings(meta, "pathsPrefix"),
            PathsRegex = Strings(meta, "pathsRegex").Select(CompileRegex).Where(rx => rx != null).Cast<Regex>().ToList(),
            Allow = MakeRangeSet(Sec(sec, 10), Sec(sec, 11), Sub(meta, "allow")),
            Challenge = MakeRangeSet(Sec(sec, 12), Sec(sec, 13), Sub(meta, "challenge")),
            Rules = CompileRules(meta, rule4, rule6),
        };
    }

    private static U32 Sec(Dictionary<uint, U32> sec, uint t) => sec.TryGetValue(t, out var s) ? s : U32.Empty;

    private static U32 SecOr(Dictionary<uint, U32> sec, uint t, int zeros) => sec.TryGetValue(t, out var s) && s.Length > 0 ? s : U32.Zeros(zeros);

    private static JsonElement Sub(JsonElement meta, string name) =>
        meta.ValueKind == JsonValueKind.Object && meta.TryGetProperty(name, out var v) ? v : default;
}

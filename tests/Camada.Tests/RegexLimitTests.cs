// Contract regex-limit v1 (camada-all-2pap): a customer `matches` regex has a bounded cost at match time.
// Vectors live in the camada-core sibling checkout (never copied here) and are pinned by sha256.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Camada.Snapshot;

namespace Camada.Tests;

public class RegexLimitTests
{
    private const string Sha = "26a8c7bdac744186870cc41ed37f2a9c1673320d84bad403c2b1ee95fba92619";
    private const string Rel = "regex-limit/regex-limit-vectors.json";

    private static readonly JsonElement V = Fixtures.ReadJson(Rel);

    private static string Text(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.String)
        {
            return e.GetString()!;
        }
        var sb = new StringBuilder(e.TryGetProperty("prefix", out var p) ? p.GetString() : "");
        sb.Insert(sb.Length, e.GetProperty("repeat").GetString()!, e.GetProperty("times").GetInt32());
        return sb.Append(e.TryGetProperty("suffix", out var s) ? s.GetString() : "").ToString();
    }

    private static MatchInput InputOf(JsonElement i) => new()
    {
        Ip = i.TryGetProperty("ip", out var ip) ? ip.GetString() : null,
        Path = i.TryGetProperty("path", out var p) ? Text(p) : null,
        Ua = i.TryGetProperty("ua", out var u) ? Text(u) : null,
    };

    /// <summary>A v5 snapshot (blk5/v5-empty.bin plus meta with rules = the given rules) behind the public matcher.</summary>
    private static Matcher MatcherOf(params JsonNode[] rules)
    {
        var meta = JsonNode.Parse(Fixtures.PathOf("blk5/v5-empty.meta.json") is var f ? File.ReadAllText(f) : "")!;
        var arr = new JsonArray();
        foreach (var r in rules)
        {
            arr.Add(JsonNode.Parse(r.ToJsonString()));
        }
        meta["rules"] = arr;
        return new Matcher(Parser.ParseSnapshot(Fixtures.ReadBin("blk5/v5-empty.bin"), JsonDocument.Parse(meta.ToJsonString()).RootElement));
    }

    private static JsonNode Rule(string id, string action, string field, string pattern) =>
        JsonNode.Parse(JsonSerializer.Serialize(new { id, action, conds = new[] { new { f = field, op = "matches", v = pattern } } }))!;

    private static bool Hit(Matcher m, MatchInput i, string id) => m.Match(i).Rule == id;

    [Fact]
    public void VectorsPinnedAndConstantsEqual()
    {
        Assert.Equal(Sha, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Fixtures.PathOf(Rel)))).ToLowerInvariant());
        var c = V.GetProperty("constants");
        Assert.Equal(Parser.MatchBudgetMs, c.GetProperty("MATCH_BUDGET_MS").GetInt32());
        Assert.Equal(Parser.RequestRegexBudgetMs, c.GetProperty("REQUEST_REGEX_BUDGET_MS").GetInt32());
        Assert.Equal(Parser.MaxMatchInput, c.GetProperty("MAX_MATCH_INPUT").GetInt32());
    }

    [Fact]
    public void BothCompilePathsCarryTheMatchBudget()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(50), Parser.CompileRegex("a+b")!.MatchTimeout);                 // ECMAScript
        // the JsToDotNet retry passes the same constant; .NET 8 ECMAScript mode refuses so few spellings that
        // no vector or probed pattern reaches it, so both `new Regex` calls are pinned by the one constant
        Assert.Equal(TimeSpan.FromMilliseconds(Parser.MatchBudgetMs), Parser.CompileRegex("[^]x")!.MatchTimeout);
    }

    [Fact]
    public void OverLimitRowsAnswerLikeOverCap()
    {
        var rows = V.GetProperty("over_limit").EnumerateArray().ToList();
        Assert.NotEmpty(rows);
        foreach (var row in rows)
        {
            var rule = JsonNode.Parse(row.GetProperty("rule").GetRawText())!;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var hit = Hit(MatcherOf(rule), InputOf(row.GetProperty("input")), (string)rule["id"]!);
            Assert.True(row.GetProperty("hit").GetProperty("budget").GetBoolean() == hit, row.GetProperty("id").GetString());
            Assert.True(sw.ElapsedMilliseconds < 2000, row.GetProperty("id").GetString());
        }
    }

    [Fact]
    public void RefusedPatternsRunNatively()
    {
        var rr = V.GetProperty("refused_rule");
        foreach (var row in V.GetProperty("refused").EnumerateArray())
        {
            var rule = Rule(rr.GetProperty("id").GetString()!, rr.GetProperty("action").GetString()!, rr.GetProperty("field").GetString()!, row.GetProperty("pattern").GetString()!);
            var m = MatcherOf(rule);
            foreach (var c in row.GetProperty("cases").EnumerateArray())
            {
                var input = new MatchInput { Ip = "8.8.8.8", Ua = Text(c.GetProperty("ua")) };
                Assert.True(c.GetProperty("hit").GetProperty("native").GetBoolean() == Hit(m, input, (string)rule["id"]!), row.GetProperty("id").GetString());
            }
        }
    }

    [Fact]
    public void RequestBudgetStopsLaterRegexes()
    {
        var row = V.GetProperty("over_limit")[1];   // OL2: a skip rule on the pathological pattern
        var pat = row.GetProperty("rule").GetProperty("conds")[0].GetProperty("v").GetString()!;
        var input = InputOf(row.GetProperty("input"));
        var slow = Enumerable.Range(0, 3).Select(n => Rule($"cr_slow{n}", "skip", "ua", pat)).ToList();
        var last = Rule("cr_last", "skip", "ua", "^a");

        // two timeouts spend the 100 ms request budget; the cheap skip rule then answers over-limit (miss) unrun
        Assert.Null(MatcherOf(slow.Append(last).ToArray()).Match(input).Rule);
        // the budget is per walk: with only the cheap rule it hits, and the thread state was reset
        Assert.Equal("cr_last", MatcherOf(last).Match(input).Rule);
        // a deny rule answers over-limit as a hit once the budget is spent
        var block = Rule("cr_block", "block", "ua", "^zzz");
        Assert.Equal("cr_block", MatcherOf(slow.Append(block).ToArray()).Match(input).Rule);
        // no walk active: only the per-match limit applies
        Assert.True(Parser.Search(Parser.CompileRegex("^a")!, "abc"));
    }
}

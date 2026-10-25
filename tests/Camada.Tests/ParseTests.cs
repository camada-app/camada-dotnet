// Container handling the golden cases do not reach: malformed input, the advisory version byte,
// and the rule-compilation rules (drop, never guess).
using System.Text.Json;
using Camada.Snapshot;

namespace Camada.Tests;

public class ParseTests
{
    private static readonly byte[] V4 = Fixtures.ReadBin("blk3/v4-basic.bin");
    private static readonly JsonElement V4Meta = Fixtures.ReadJson("blk3/v4-basic.meta.json");

    /// <summary>A tiny BLK container: header then the sections back to back.</summary>
    internal static byte[] Container(uint magic, params (int Type, uint[] Words)[] sections)
    {
        var k = sections.Length;
        var header = new List<uint> { magic, (uint)k };
        var off = 2 + k * 3;
        var body = new List<uint>();
        foreach (var (t, words) in sections)
        {
            header.AddRange(new[] { (uint)t, (uint)off, (uint)words.Length });
            body.AddRange(words);
            off += words.Length;
        }
        var all = header.Concat(body).ToArray();
        var bytes = new byte[all.Length * 4];
        for (var i = 0; i < all.Length; i++)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(i * 4), all[i]);
        }
        return bytes;
    }

    private static JsonElement Meta(string json) => JsonDocument.Parse(json).RootElement;

    internal static Matcher RulesSnapshot(string rulesJson, params (int Type, uint[] Words)[] sections) =>
        new(Parser.ParseSnapshot(Container(0x424C4B35, sections), Meta($$"""{"version":"v","rules":{{rulesJson}}}""")));

    [Fact]
    public void BadMagicAndTruncationThrow()
    {
        Assert.Throws<SnapshotFormatException>(() => Parser.ParseSnapshot("nope"u8.ToArray(), Meta("""{"version":"1"}""")));
        Assert.Throws<SnapshotFormatException>(() => Parser.ParseSnapshot(Container(0x424C4B35).Concat(new byte[] { 3, 0, 0, 0 }).Skip(4).Take(8).ToArray(), Meta("""{"version":"1"}""")));   // claims 3 sections, has none
        Assert.Throws<SnapshotFormatException>(() => Parser.ParseSnapshot(Words(0x424C4B35, 1, 10, 5, 100), Meta("""{"version":"1"}""")));   // section runs past the end
    }

    private static byte[] Words(params uint[] words)
    {
        var bytes = new byte[words.Length * 4];
        for (var i = 0; i < words.Length; i++)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(i * 4), words[i]);
        }
        return bytes;
    }

    [Fact]
    public void UnalignedTailIsDroppedNotFatal()
    {
        var snap = Parser.ParseSnapshot(V4.Concat(new byte[] { 1 }).ToArray(), V4Meta);
        Assert.Equal(4, snap.Format);
    }

    [Fact]
    public void AMemorySliceParsesInPlace()
    {
        // the client hands the parser a slice of the frame (after the meta), never a copy
        var framed = new byte[] { 9, 9, 9 }.Concat(V4).ToArray();
        var snap = Parser.ParseSnapshot(new ReadOnlyMemory<byte>(framed, 3, V4.Length), V4Meta);
        Assert.Equal("ip4", new Matcher(snap).Match(new MatchInput { Ip = "203.0.113.66" }).Reason);
    }

    [Fact]
    public void V3MagicStillReadsV4Sections()
    {
        // the version byte is advisory: an allow range under a BLK3 magic still allows
        var n = (192u << 24) | (0u << 16) | (2u << 8) | 20;
        var bin3 = Container(0x424C4B33, (10, new[] { n, n }));
        var r = new Matcher(Parser.ParseSnapshot(bin3, Meta("""{"version":"x"}"""))).Match(new MatchInput { Ip = "192.0.2.20" });
        Assert.True(r.Allowed);
        Assert.Equal("ip4", r.Reason);
        Assert.Equal(3, Parser.ParseSnapshot(bin3, Meta("""{"version":"x"}""")).Format);
    }

    [Fact]
    public void UnknownActionAndEmptyRulesAreDropped()
    {
        var m = RulesSnapshot("""
            [{"id":"a","action":"teleport","conds":[{"f":"path","op":"is","v":"/x"}]},
             {"id":"b","action":"block","conds":[]},
             {"id":"c","action":"block","conds":[{"f":"path","op":"is","v":"/x"}]}]
            """);
        Assert.Equal(new[] { "c" }, m.Snap.Rules.Select(r => r.Id));
        Assert.Equal("c", m.Match(new MatchInput { Path = "/x" }).Rule);
    }

    [Fact]
    public void RegexTheRuntimeRejectsNeverMatchesAndNeverThrows()
    {
        var m = RulesSnapshot("""[{"id":"bad","action":"block","conds":[{"f":"path","op":"matches","v":"(?<=a"}]}]""");
        Assert.False(m.Match(new MatchInput { Path = "/a" }).Block);
        var m2 = new Matcher(Parser.ParseSnapshot(Container(0x424C4B35), Meta("""{"version":"v","pathsRegex":["(?<=a","^/dump$"]}""")));
        Assert.Equal("path", m2.Match(new MatchInput { Path = "/dump" }).Reason);
    }

    private static Matcher MetaRegex(string rulesJson, string pattern) =>
        new(Parser.ParseSnapshot(Container(0x424C4B35), Meta($$"""{"version":"v","pathsRegex":["{{pattern}}"],"rules":{{rulesJson}}}""")));

    [Fact]
    public void MetaPathsRegexIsCaseInsensitive()
    {
        var m = MetaRegex("[]", "^/DUMP$");
        Assert.Equal("path", m.Match(new MatchInput { Path = "/dump" }).Reason);
        Assert.False(m.Match(new MatchInput { Path = "/dumpx" }).Block);
    }

    [Fact]
    public void MetaPathsRegexTheRuntimeRefusesNeverMatches()
    {
        var m = MetaRegex("[]", "(?<=a");
        Assert.False(m.Match(new MatchInput { Path = "/a" }).Block);
    }

    [Fact]
    public void MetaPathsRegexOnAPathOverTheCapBlocks()
    {
        var m = MetaRegex("[]", "^/never$");
        var over = m.Match(new MatchInput { Path = "/" + new string('a', Parser.MaxMatchInput) });
        Assert.True(over.Block);
        Assert.Equal("path", over.Reason);
        Assert.False(m.Match(new MatchInput { Path = "/" + new string('a', Parser.MaxMatchInput - 1) }).Block);
    }

    [Fact]
    public void MetaPathsRegexSharesTheRuleWalksRequestBudget()
    {
        var field = typeof(Parser).GetField("_budgetLeft", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var rules = """[{"id":"h","action":"block","conds":[{"f":"header","op":"is","name":"x-spend","v":"never"}]}]""";
        var m = MetaRegex(rules, "^/never$");
        var spend = m.Match(new MatchInput { Path = "/x", Header = _ => { field.SetValue(null, (long?)0); return null; } });
        Assert.True(spend.Block);
        Assert.Equal("path", spend.Reason);
        Assert.False(m.Match(new MatchInput { Path = "/x", Header = _ => null }).Block);
    }

    [Fact]
    public void ACatastrophicPatternTimingOutFailsClosedForDenyAndMissForSkip()
    {
        string slow = new string('a', 40) + "b";
        var deny = RulesSnapshot("""[{"id":"slow","action":"block","conds":[{"f":"ua","op":"matches","v":"^(a+)+$"}]}]""");
        Assert.True(deny.Match(new MatchInput { Ua = slow }).Block);      // the 50 ms timeout answers deny
        Assert.True(deny.Match(new MatchInput { Ua = "aaa" }).Block);
        Assert.False(deny.Match(new MatchInput { Ua = "aab " }).Block);
        var path = RulesSnapshot("""[{"id":"sp","action":"block","conds":[{"f":"path","op":"matches","v":"^/(a+)+$"}]}]""");
        Assert.True(path.Match(new MatchInput { Path = "/" + slow }).Block);
        var skip = RulesSnapshot("""
            [{"id":"s","action":"skip","conds":[{"f":"ua","op":"matches","v":"^(a+)+$"}]},
             {"id":"e","action":"warn","conds":[{"f":"ua","op":"contains","v":"b"}]}]
            """);
        Assert.Equal("e", Rule(skip, new MatchInput { Ua = slow }));       // a skip rule misses
    }

    [Fact]
    public void SearchAnswersTheCallersFailureValueOnATimeout()
    {
        var rx = new System.Text.RegularExpressions.Regex("^(a+)+$", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(1));
        string slow = new string('a', 40) + "b";
        Assert.True(Parser.Search(rx, slow, onFailure: true));
        Assert.False(Parser.Search(rx, slow));
    }

    [Fact]
    public void AsnConditionsCompareAsStringsAndUnanswerableFieldsNeverFire()
    {
        var m = RulesSnapshot("""
            [{"id":"asn","action":"block","conds":[{"f":"asn","op":"is_in","v":[14061,"7922"]}]},
             {"id":"cc","action":"block","conds":[{"f":"country","op":"is_not","v":"US"}]}]
            """);
        Assert.Equal("asn", m.Match(new MatchInput { Asn = 14061 }).Rule);
        Assert.Equal("asn", m.Match(new MatchInput { Asn = 7922 }).Rule);
        Assert.Null(m.Match(new MatchInput { Asn = 1 }).Rule);         // country unanswerable: is_not stays false
        Assert.Equal("cc", m.Match(new MatchInput { Country = "BR" }).Rule);
    }

    [Fact]
    public void HeaderGetterThatThrowsReadsAsAbsent()
    {
        var m = RulesSnapshot("""[{"id":"h","action":"block","conds":[{"f":"header","op":"is","name":"X-Api-Key","v":"k"}]}]""");
        Assert.False(m.Match(new MatchInput { Header = _ => throw new InvalidOperationException("app bug") }).Block);
        Assert.Equal("h", m.Match(new MatchInput { Header = n => n == "x-api-key" ? "k" : null }).Rule);
        Assert.False(m.Match(new MatchInput { Header = n => n == "x-api-key" ? "other" : null }).Block);
    }

    [Fact]
    public void TwoIpConditionsConsumeTwoSectionPairsInOrder()
    {
        var a = (10u << 24) | 1;
        var b = (10u << 24) | 2;
        var m = RulesSnapshot(
            """[{"id":"r","action":"block","conds":[{"f":"ip","op":"is_in","set":true},{"f":"ip","op":"not_in","set":true}]}]""",
            (14, new[] { 0u, a, a }), (15, new[] { 0u }), (14, new[] { 0u, b, b }), (15, new[] { 0u }));
        Assert.Equal("r", m.Match(new MatchInput { Ip = "10.0.0.1" }).Rule);   // in the first, not in the second
        Assert.Null(m.Match(new MatchInput { Ip = "10.0.0.2" }).Rule);         // not in the first
    }

    [Fact]
    public void JsRegexSpellingsAreTranslated()
    {
        var m = RulesSnapshot("""[{"id":"ver","action":"block","conds":[{"f":"path","op":"matches","v":"^/api/(?<ver>v\\d+)/"}]}]""");
        Assert.Equal("ver", m.Match(new MatchInput { Path = "/api/v2/dump" }).Rule);
        Assert.Null(m.Match(new MatchInput { Path = "/api/v٣/dump" }).Rule);   // \d is ASCII, as JS reads it
        var m2 = RulesSnapshot("""[{"id":"any","action":"block","conds":[{"f":"ua","op":"matches","v":"^a[^]b$"}]}]""");
        Assert.Equal("any", m2.Match(new MatchInput { Ua = "a b" }).Rule);
        Assert.Null(m2.Match(new MatchInput { Ua = "ab" }).Rule);
    }

    [Fact]
    public void ThePatternTranslatorCoversTheJsOnlySpellings()
    {
        Assert.Equal("[\\s\\S]x", Parser.JsToDotNet("[^]x"));
        Assert.Equal("[\\s\\S]]", Parser.JsToDotNet("[^]]"));       // JS: any char, then a literal ]
        Assert.Equal("[a^]", Parser.JsToDotNet("[a^]"));           // inside a class: untouched
        Assert.Equal("\\[^]", Parser.JsToDotNet("\\[^]"));         // escaped: untouched
        Assert.NotNull(Parser.CompileRegex("(?i)^/admin"));       // an inline flag ECMAScript mode refuses still compiles on the fallback
        Assert.Matches(Parser.CompileRegex("(?i)^/admin")!, "/ADMIN");
    }

    [Fact]
    public void OneMatcherServesConcurrentRequestsWithoutCrosstalk()
    {
        var a = (10u << 24) | 1;
        var m = RulesSnapshot(
            """[{"id":"r","action":"block","conds":[{"f":"header","op":"is","name":"x-a","v":"1"},{"f":"ip","op":"is_in","set":true}]}]""",
            (14, new[] { 0u, a, a }), (15, new[] { 0u }));
        string Header(string _)
        {
            Thread.Yield();   // hand the core to the other request between the header read and the ip check
            return "1";
        }
        var wrong = new int[2];
        void Hammer(int slot, string ip, bool expect)
        {
            for (var i = 0; i < 1500; i++)
            {
                if (m.Match(new MatchInput { Ip = ip, Header = Header }).Block != expect)
                {
                    wrong[slot]++;
                }
            }
        }
        var t1 = new Thread(() => Hammer(0, "10.0.0.1", true));
        var t2 = new Thread(() => Hammer(1, "10.0.0.2", false));
        t1.Start();
        t2.Start();
        t1.Join();
        t2.Join();
        Assert.Equal(new[] { 0, 0 }, wrong);
    }

    private static string MRule(string id, string action, string f, string? name, string rx) =>
        "{\"id\":\"" + id + "\",\"action\":\"" + action + "\",\"conds\":[{\"f\":\"" + f + "\",\"op\":\"matches\","
        + (name == null ? "" : "\"name\":\"" + name + "\",") + "\"v\":\"" + rx.Replace("\\", "\\\\") + "\"}]}";

    private static string? Rule(Matcher m, MatchInput i) => m.Match(i).Rule;

    [Fact]
    public void MatchesCapsInputFailingClosedForDenyAndMissForSkip()
    {
        var deny = RulesSnapshot("[" + string.Join(",", MRule("u", "warn", "ua", null, "(Scrapy|python-requests)/[0-9]"),
            MRule("h", "challenge", "header", "x-v", @"^1\.[0-2]\."), MRule("p", "block", "path", null, "^/api/v[0-9]+/dump$")) + "]");
        string? Ua(string v) => Rule(deny, new MatchInput { Ua = v });
        string? Hd(string v) => Rule(deny, new MatchInput { Header = _ => v });
        string? Pa(string v) => Rule(deny, new MatchInput { Path = v });
        Assert.Null(Ua(new string('a', 2048)));
        Assert.Equal("u", Ua(new string('a', 2049)));
        Assert.Null(Ua(string.Concat(Enumerable.Repeat("é", 2048))));
        Assert.Null(Ua(string.Concat(Enumerable.Repeat("😀", 1024))));
        Assert.Equal("u", Ua(string.Concat(Enumerable.Repeat("😀", 1025))));
        // camada-all-wh9m: a deny reads the raw value too; raw 2049 is over the cap (v2 pinned a miss)
        Assert.Equal("u", Ua("Mozilla/5.0 " + new string('a', 2036) + "\t"));
        Assert.Equal("h", Hd(new string('9', 2049)));
        Assert.Null(Hd(new string('9', 2048)));
        Assert.Null(Pa("/x/" + new string('a', 2045)));
        Assert.Equal("p", Pa("/x/" + new string('a', 2046)));
        Assert.Equal("p", Pa("/" + string.Concat(Enumerable.Repeat("%61", 700))));
        Assert.Null(Pa("/x?" + new string('q', 3000)));

        var skip = RulesSnapshot("[" + string.Join(",", MRule("s", "skip", "ua", null, "^uptime-probe/[0-9]"),
            MRule("sp", "skip", "path", null, "^/static-mirror/"), MRule("e", "warn", "ua", null, "Scrapy"),
            MRule("c", "block", "path", null, "^/api/v[0-9]+/dump$")) + "]");
        const string up = "uptime-probe/1 ";
        const string sm = "/static-mirror/";
        Assert.Equal("s", Rule(skip, new MatchInput { Ua = up + new string('a', 2033) }));
        Assert.Equal("e", Rule(skip, new MatchInput { Ua = up + new string('a', 2034) }));
        Assert.Equal("sp", Rule(skip, new MatchInput { Path = sm + new string('a', 2033) }));
        Assert.Equal("c", Rule(skip, new MatchInput { Path = sm + new string('a', 2034) }));
        Assert.Equal("sp", Rule(skip, new MatchInput { Path = sm + string.Concat(Enumerable.Repeat("%61", 700)) }));
        Assert.Equal("c", Rule(skip, new MatchInput { Path = sm + string.Concat(Enumerable.Repeat("./", 1100)) + "x" }));
    }

    [Fact]
    public void DenyReadsRawAndStrippedAndSkipNeverTakesAControlChar()
    {
        var m = RulesSnapshot("[" + string.Join(",", MRule("t", "block", "ua", null, @"a\tb"), MRule("q", "block", "ua", null, "sqlmap"),
            MRule("ht", "block", "header", "x-h", @"a\tb"), MRule("hq", "block", "header", "x-q", "sqlmap")) + "]");
        Assert.Equal("t", Rule(m, new MatchInput { Ua = "a\tb" }));
        Assert.Equal("q", Rule(m, new MatchInput { Ua = "sql\tmap" }));
        Assert.Null(Rule(m, new MatchInput { Ua = "ab" }));
        Assert.Equal("ht", Rule(m, new MatchInput { Header = n => n == "x-h" ? "a\tb" : null }));
        Assert.Equal("hq", Rule(m, new MatchInput { Header = n => n == "x-q" ? "sql\tmap" : null }));
        var s = RulesSnapshot("[" + string.Join(",", MRule("s", "skip", "ua", null, "^partner-[a-z]+$"), MRule("d", "block", "ua", null, "partner")) + "]");
        Assert.Equal("s", Rule(s, new MatchInput { Ua = "partner-acme" }));
        Assert.Equal("d", Rule(s, new MatchInput { Ua = "partner-acme\n" }));
        var o = RulesSnapshot("[" + string.Join(",", MRule("s", "skip", "ua", null, "^a+$"), MRule("d", "block", "ua", null, "^zzz$")) + "]");
        Assert.Equal("d", Rule(o, new MatchInput { Ua = new string('a', 2048) + "\t" }));
        Assert.Equal("s", Rule(o, new MatchInput { Ua = new string('a', 2048) }));
    }

    [Fact]
    public void ControlCharsAreStrippedFromUaAndHeaderForMatchesOnly()
    {
        var m = RulesSnapshot("[" + string.Join(",", MRule("e", "warn", "ua", null, "(Scrapy|python-requests)/[0-9]"),
            MRule("s", "skip", "header", "x-p", "^partner-[a-z]+$"),
            """{"id":"k","action":"block","conds":[{"f":"ua","op":"contains","v":"curl/"}]}""",
            MRule("c", "block", "path", null, "^/api/v[0-9]+/dump$")) + "]");
        Assert.Equal("e", Rule(m, new MatchInput { Ua = "python-requests\0/2.32.0" }));
        Assert.Equal("e", Rule(m, new MatchInput { Ua = "Scrapy\t/2.11" }));
        Assert.Equal("e", Rule(m, new MatchInput { Ua = "python-requests/\x7f" + "2" }));
        Assert.Null(Rule(m, new MatchInput { Ua = "cu\0rl/8.4.0" }));
        // a skip never exempts a value with a control char (v2 pinned "s")
        Assert.Null(Rule(m, new MatchInput { Header = _ => "partner-acme\n" }));
        Assert.Equal("s", Rule(m, new MatchInput { Header = _ => "partner-acme" }));
        Assert.Null(Rule(m, new MatchInput { Path = "/api/v2/dump\n" }));
        Assert.Null(Rule(m, new MatchInput { Path = "/api/v2/dump%0A" }));
        Assert.Equal("c", Rule(m, new MatchInput { Path = "/api/v2/dump" }));
        Assert.Equal(new[] { "/a%0a%7f", "/a%0a%7f", "/a%0a%7f" }, Paths.Forms("/a\n\x7f"));
    }

    [Fact]
    public void PathHitTriesARepeatedFormOnce()
    {
        var n = 0;
        Func<string, bool> no = _ => ++n < 0, yes = _ => ++n > 0;
        var same = Paths.Forms("/a/b");
        string[] three = ["/a", "/b", "/c"], repeat = ["/a", "/b", "/b"];
        Assert.False(Paths.Hit(no, same, true));
        Assert.Equal(1, n);
        n = 0;
        Assert.True(Paths.Hit(yes, same, false));
        Assert.Equal(1, n);
        n = 0;
        Assert.False(Paths.Hit(no, same, false));
        Assert.Equal(1, n);
        n = 0;
        Assert.False(Paths.Hit(no, three, true));
        Assert.Equal(3, n);
        n = 0;
        Assert.False(Paths.Hit(no, repeat, true));
        Assert.Equal(2, n);
        n = 0;
        Assert.False(Paths.Hit(no, three, false));
        Assert.Equal(1, n);
        Assert.True(Paths.Hit(p => p == "/c", three, true));
        Assert.True(Paths.Hit(p => p == "/b", repeat, true));
        Assert.False(Paths.Hit(p => p == "/b", three, false));
        Assert.True(Paths.Hit(p => p != "/a", three, false));
    }
}

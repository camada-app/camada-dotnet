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

    private static Matcher RulesSnapshot(string rulesJson, params (int Type, uint[] Words)[] sections) =>
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

    [Fact]
    public void ACatastrophicPatternTimesOutAsNoMatch()
    {
        var m = RulesSnapshot("""[{"id":"slow","action":"block","conds":[{"f":"ua","op":"matches","v":"^(a+)+$"}]}]""");
        Assert.False(m.Match(new MatchInput { Ua = new string('a', 40) + "b" }).Block);
        Assert.True(m.Match(new MatchInput { Ua = "aaa" }).Block);
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
        var m2 = RulesSnapshot("""[{"id":"any","action":"block","conds":[{"f":"ua","op":"matches","v":"^a[^]b\\cJ$"}]}]""");
        Assert.Equal("any", m2.Match(new MatchInput { Ua = "a\nb\n" }).Rule);
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
}

// The SDK conformance cases (contract C6) every server SDK runs: client-IP resolution
// (camada-all-0vho XFF ports, camada-all-yfc6 peer-first cidrs walk), the Referer scrub and the
// request's own query scrub (camada-all-ijsa), fixture version 3. The files live in camada-core/test/fixtures; a missing file fails by name,
// never skips. No case is skipped here. Configs go through Config.TrustedProxyOf, the same parse
// the analyst-delivered tenant config takes.
using System.Text.Encodings.Web;
using System.Text.Json;
using Camada.Events;

namespace Camada.Tests;

public class SdkConformanceTests
{
    public static TheoryData<string> IpCaseIds() => Ids("ip/resolve.json");

    public static TheoryData<string> RefererCaseIds() => Ids("redact/referer.json");

    public static TheoryData<string> QueryCaseIds() => Ids("redact/query.json");

    public static TheoryData<string> TokenCaseIds() => Ids("redact/token.json");

    private static TheoryData<string> Ids(string rel)
    {
        var data = new TheoryData<string>();
        foreach (var c in Fixtures.ReadJson(rel).GetProperty("cases").EnumerateArray())
        {
            data.Add(c.GetProperty("id").GetString()!);
        }
        Assert.NotEmpty(data);
        return data;
    }

    private static JsonElement Case(string rel, string id) =>
        Fixtures.ReadJson(rel).GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    [Theory]
    [MemberData(nameof(IpCaseIds))]
    public void ResolveClientIp(string id)
    {
        var c = Case("ip/resolve.json", id);
        var configs = Fixtures.ReadJson("ip/resolve.json").GetProperty("configs");
        Assert.True(configs.TryGetProperty(c.GetProperty("config").GetString()!, out var cfg), $"{id}: unknown config");
        Assert.Equal(Str(c, "expect"), Ip.ResolveClientIp(Str(c, "peer"), Str(c, "xff"), Config.TrustedProxyOf(cfg)));
    }

    [Theory]
    [MemberData(nameof(RefererCaseIds))]
    public void RefererRedaction(string id)
    {
        var c = Case("redact/referer.json", id);
        var headers = new List<KeyValuePair<string, string>> { new("accept", "text/html") };
        if (Str(c, "referer") is { } referer)
        {
            headers.Add(new("referer", referer));
        }
        var ev = Builder.BuildWireEvent(new RequestInfo("GET", "shop.test", "/api/me", "", headers, "1.2.3.4", "1.1"), tap: "sdk-dotnet", rid: "r1");
        Assert.Equal(Str(c, "ref"), ev["ref"]);
        var json = JsonSerializer.Serialize(ev, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        if (c.TryGetProperty("absent", out var absent))
        {
            foreach (var secret in absent.EnumerateArray())
            {
                Assert.DoesNotContain(secret.GetString()!, json);
            }
        }
    }

    [Theory]
    [MemberData(nameof(QueryCaseIds))]
    public void QueryRedaction(string id)
    {
        var c = Case("redact/query.json", id);
        var headers = new List<KeyValuePair<string, string>> { new("accept", "text/html") };
        var ev = Builder.BuildWireEvent(new RequestInfo("GET", "shop.test", "/api/me", Str(c, "query")!, headers, "1.2.3.4", "1.1"), tap: "sdk-dotnet", rid: "r1");
        Assert.Equal(Str(c, "q"), ev["q"]);
        var json = JsonSerializer.Serialize(ev, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        if (c.TryGetProperty("absent", out var absent))
        {
            foreach (var secret in absent.EnumerateArray())
            {
                Assert.DoesNotContain(secret.GetString()!, json);
            }
        }
    }

    [Theory]
    [MemberData(nameof(TokenCaseIds))]
    public void TokenHash(string id)
    {
        var c = Case("redact/token.json", id);
        var (header, invalid) = Config.ResolveTokenHeader(Str(c, "tokenHeader"), null);
        Assert.False(invalid);
        var key = Str(c, "key")!;
        var first = c.GetProperty("headers").EnumerateObject()
            .ToDictionary(p => p.Name, p => p.Value.GetString()!, StringComparer.Ordinal);
        Assert.Equal(Str(c, "credential"), Redact.SelectCredential(first, header));

        var req = new RequestInfo("GET", "shop.test", "/api/me", "", first.ToList(), "1.2.3.4", "1.1");
        var ev = Builder.BuildWireEvent(req, tap: "sdk-dotnet", rid: "r1", token: new(header, v => Redact.HashToken(v, key)));
        if (Str(c, "tk") is { } hash)
        {
            Assert.Equal(hash, ev["tk"]);
        }
        else
        {
            Assert.DoesNotContain("tk", ev.Keys);
        }
    }

    [Fact]
    public void TokenFixtureHasAllVersion1Cases()
    {
        var doc = Fixtures.ReadJson("redact/token.json");
        Assert.Equal(1, doc.GetProperty("version").GetInt32());
        Assert.Equal(22, doc.GetProperty("cases").GetArrayLength());
    }

    [Theory]
    [InlineData("ip/resolve.json", 100)]
    [InlineData("redact/referer.json", 47)]
    [InlineData("redact/query.json", 39)]
    public void FixturesAreVersion3(string rel, int count)
    {
        var doc = Fixtures.ReadJson(rel);
        Assert.Equal(3, doc.GetProperty("version").GetInt32());
        Assert.Equal(count, doc.GetProperty("cases").GetArrayLength());
    }
}

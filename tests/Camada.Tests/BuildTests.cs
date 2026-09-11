// The wire event reproduces the collector's record(); HDRS bit order is pinned by the shared
// fixture (ConformanceTests) — here the derived counters and the credential rules.
using Camada.Events;

namespace Camada.Tests;

public class BuildTests
{
    private static RequestInfo Req(IList<KeyValuePair<string, string>> headers, string query = "", string? ip = "1.2.3.4") =>
        new("GET", "x.test", "/p", query, headers, ip, "1.1");

    private static KeyValuePair<string, string> H(string k, string v) => new(k, v);

    [Fact]
    public void AuthSchemeOnlyEverShipsAScheme()
    {
        Assert.Equal("Bearer", Builder.AuthScheme("Bearer abc.def"));
        Assert.Equal("Basic", Builder.AuthScheme("Basic dXNlcjpwYXNz"));
        Assert.Null(Builder.AuthScheme("rawtoken"));
        Assert.Null(Builder.AuthScheme(" Bearer x"));
        Assert.Null(Builder.AuthScheme(new string('a', 17) + " x"));
        Assert.Null(Builder.AuthScheme(null));
    }

    [Fact]
    public void EventFieldsAndCounters()
    {
        var headers = new[] { H("Accept", "text/html"), H("Cookie", "a=1; b=2"), H("Authorization", "Bearer t"), H("Accept", "*/*"), H("User-Agent", "ua") };
        var ev = Builder.BuildWireEvent(Req(headers, query: "?x=1&token=t&&y"), tap: "sdk-dotnet", rid: "r1", sid: "s1", newSession: true);
        Assert.Equal("sdk-dotnet", ev["tap"]);
        Assert.Equal("r1", ev["rid"]);
        Assert.Equal("s1", ev["sid"]);
        Assert.Equal(1, ev["ns"]);
        Assert.Equal("GET", ev["m"]);
        Assert.Equal("x.test", ev["h"]);
        Assert.Equal("/p", ev["p"]);
        Assert.Equal("HTTP/1.1", ev["proto"]);
        Assert.Equal("?x=1&token=~r&&y", ev["q"]);
        Assert.Equal(3, ev["qn"]);
        Assert.Equal("text/html", ev["acc"]);          // first occurrence wins
        Assert.Equal("Bearer", ev["auth"]);
        Assert.Equal(2, ev["ck"]);
        Assert.Equal(5, ev["hn"]);
        Assert.Equal(headers.Sum(h => h.Key.Length + h.Value.Length), ev["hb"]);
        Assert.Equal("accept,cookie,authorization,accept,user-agent", ev["hord"]);
        var idx = (string n) => Array.IndexOf(Builder.Hdrs, n);
        Assert.Equal((1 << idx("accept")) | (1 << idx("cookie")) | (1 << idx("authorization")), ev["hm"]);
        Assert.Equal("ua", ev["ua"]);
        Assert.Null(ev["st"]);
        Assert.Null(ev["dur"]);
        Assert.IsType<long>(ev["ts"]);
        Assert.False(ev.ContainsKey("ja4"));
    }

    [Fact]
    public void EventWithoutHeadersOrIp()
    {
        var ev = Builder.BuildWireEvent(Req(Array.Empty<KeyValuePair<string, string>>(), ip: null), tap: "sdk-dotnet", rid: "r");
        Assert.Null(ev["ip"]);
        Assert.Null(ev["sid"]);
        Assert.Equal(0, ev["ns"]);
        Assert.Equal(0, ev["hm"]);
        Assert.Equal(0, ev["hn"]);
        Assert.Equal(0, ev["hb"]);
        Assert.Equal(0, ev["ck"]);
        Assert.Equal("", ev["hord"]);
        Assert.Equal(0, ev["qn"]);
        Assert.Equal("", ev["q"]);
    }

    [Fact]
    public void HordAndQueryAreCapped()
    {
        var headers = Enumerable.Range(0, 1000).Select(i => H("x-" + i, "v")).ToList();
        var ev = Builder.BuildWireEvent(Req(headers, query: "?" + new string('a', 600)), tap: "sdk-dotnet", rid: "r");
        Assert.Equal(2048, ((string)ev["hord"]!).Length);
        Assert.Equal(512, ((string)ev["q"]!).Length);
    }

    [Fact]
    public void TheEventSerialisesAsTheWireJson()
    {
        var ev = Builder.BuildWireEvent(Req(new[] { H("cookie", "a=1") }), tap: "sdk-dotnet", rid: "r");
        ev["st"] = 200;
        var json = System.Text.Json.JsonSerializer.Serialize(ev);
        Assert.Contains("\"st\":200", json);
        Assert.Contains("\"dur\":null", json);
        Assert.Contains("\"ck\":1", json);
        Assert.DoesNotContain("a=1", json);   // cookie values never ship
    }
}

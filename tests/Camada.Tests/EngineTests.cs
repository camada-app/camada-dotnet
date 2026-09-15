// The engine through the ASP.NET Core middleware: inline enforcement, ordered custom rules, the
// challenge, the first-party beacon, request capture, app-context events, and the fail-open
// envelope. The case list mirrors camada-python's test_engine.py (one host here: the middleware).
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Camada.Tests;

public static class EngineFx
{
    public static readonly (string, string)[] Html = { ("accept", "text/html,*/*"), ("sec-fetch-dest", "document") };

    public static (string, string)[] Ip(string addr) => new[] { ("x-forwarded-for", addr) };

    public static void Hops1(FakeAnalyst a) => a.Config["trusted_proxy"] = new Dictionary<string, object?> { ["mode"] = "hops", ["hops"] = 1 };

    public static readonly Dictionary<string, string?> Hops1Env = new() { ["CAMADA_TRUSTED_PROXY"] = "hops:1" };

    public static string Nonce(string page) => page.Split("name=\"nonce\" value=\"")[1].Split('"')[0];

    public static Func<HttpContext, Task> Respond(int status, (string, string)[] headers, string body) => ctx =>
    {
        ctx.Response.StatusCode = status;
        foreach (var (k, v) in headers)
        {
            ctx.Response.Headers.Append(k, v);
        }
        return ctx.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(body)).AsTask();
    };

    public static CamadaContext Ctx(HttpContext ctx) => (CamadaContext)ctx.Items["camada"]!;
}

public class InlineBlockingTests
{
    [Fact]
    public void Answers403BeforeTheAppAndStillShipsTheEvent()
    {
        var a = new FakeAnalyst();
        using var h = new Host(a, EngineFx.Hops1Env);
        var r = h.Call("GET", "/admin?x=1", EngineFx.Ip(FakeAnalyst.BlockedIp));
        Assert.Equal(403, r.Status);
        Assert.Equal("Forbidden", r.Text);
        Assert.Equal("ip4", r.Header("x-block-reason"));
        Assert.Equal(a.MetaVersion, r.Header("x-block-version"));
        Assert.Equal("text/plain", r.Header("content-type"));
        Assert.Null(r.Header("x-block-rule"));
        Assert.Empty(h.Seen);
        var ev = Assert.Single(h.Events());
        Assert.Equal(403, ev.I("st"));
        Assert.Equal("ip4", ev.S("blk"));
        Assert.Equal(FakeAnalyst.BlockedIp, ev.S("ip"));
        Assert.Equal("/admin", ev.S("p"));
        Assert.Equal("sdk-dotnet", ev.S("tap"));
        Assert.False(ev.ContainsKey("rl"));
    }

    [Fact]
    public void IgnoresASpoofedXffWithoutTrustedProxyConfig()
    {
        using var h = new Host(new FakeAnalyst());
        Assert.Equal(200, h.Call("GET", "/", EngineFx.Ip(FakeAnalyst.BlockedIp)).Status);
        Assert.Equal(403, h.Call("GET", "/", peer: FakeAnalyst.BlockedIp).Status);
    }

    [Fact]
    public void ServerDeliveredTrustedProxyAppliesWhenNoLocalOverride()
    {
        var a = new FakeAnalyst();
        EngineFx.Hops1(a);
        using var h = new Host(a);
        Assert.Equal(403, h.Call("GET", "/", EngineFx.Ip(FakeAnalyst.BlockedIp)).Status);
    }

    [Fact]
    public void FailsOpenWhileCold()
    {
        using var h = new Host(new FakeAnalyst { SnapshotDown = true }, load: false);
        Assert.Equal(200, h.Call("GET", "/", peer: FakeAnalyst.BlockedIp).Status);
        Assert.Single(h.Seen);
    }

    [Fact]
    public void HonoursTheAllowSideOverAWiderBlock()
    {
        using var h = new Host(new FakeAnalyst { Container = "v4" });
        Assert.Equal(403, h.Call("GET", "/", peer: "10.0.0.9").Status);
        Assert.Equal(200, h.Call("GET", "/", peer: FakeAnalyst.AllowedIp).Status);
    }

    [Fact]
    public void AV4MappedPeerIsReadAsItsV4Address()
    {
        using var h = new Host(new FakeAnalyst());
        Assert.Equal(403, h.Call("GET", "/", peer: "::ffff:" + FakeAnalyst.BlockedIp).Status);
    }
}

public class SdkIdentityTests
{
    [Fact]
    public void SendsXCamadaSdkOnPollsAndBatches()
    {
        var a = new FakeAnalyst();
        using var h = new Host(a);
        h.Call("GET", "/");
        h.Events();
        Assert.Equal(new HashSet<string> { CamadaVersion.SdkId }, a.SdkHeaders.ToHashSet());
        Assert.True(a.SdkHeaders.Count >= 2);
    }

    [Fact]
    public void AsksForV5ByDefaultAndOptsOutAt3()
    {
        var a = new FakeAnalyst();
        using var h1 = new Host(a);
        using var h2 = new Host(a, configure: o => o.SnapshotVersion = 3);
        Assert.Equal(new[] { "5", "" }, a.SnapshotVersions.Take(2));
    }
}

public class CaptureTests
{
    [Fact]
    public void CapturesOnFinishWithStatusLatencySessionAndRid()
    {
        using var h = new Host(new FakeAnalyst(), handler: EngineFx.Respond(201, new[] { ("x-app", "1") }, "made"));
        var r = h.Call("POST", "/things?q=1&token=secret", new[] { ("user-agent", "UA/1"), ("accept", "*/*") }, "{}"u8.ToArray());
        Assert.Equal(201, r.Status);
        Assert.Equal("made", r.Text);
        Assert.Equal("1", r.Header("x-app"));
        var rid = r.Header("x-rid");
        Assert.NotNull(rid);
        Assert.Equal(36, rid!.Length);
        var cookie = r.Header("set-cookie");
        Assert.NotNull(cookie);
        Assert.StartsWith("_sfp=", cookie);
        Assert.Contains("HttpOnly", cookie);
        Assert.Contains("SameSite=Lax", cookie);
        Assert.DoesNotContain("Secure", cookie);
        var ev = Assert.Single(h.Events());
        Assert.Equal(rid, ev.S("rid"));
        Assert.Equal(cookie![5..].Split(';')[0], ev.S("sid"));
        Assert.Equal(1, ev.I("ns"));
        Assert.Equal(201, ev.I("st"));
        Assert.True(ev.I("dur") >= 0);
        Assert.Equal("POST", ev.S("m"));
        Assert.Equal("/things", ev.S("p"));
        Assert.Equal("?q=1&token=~r", ev.S("q"));
        Assert.Equal("UA/1", ev.S("ua"));
        Assert.Equal(Hosts.Peer, ev.S("ip"));
        Assert.Equal("HTTP/1.1", ev.S("proto"));
        Assert.Equal("x.test", ev.S("h"));
        Assert.False(ev.ContainsKey("blk"));
        Assert.False(ev.ContainsKey("wrn"));
    }

    [Fact]
    public void ReusesTheSessionCookieAndMarksHttpsSecure()
    {
        using var h = new Host(new FakeAnalyst());
        var r = h.Call("GET", "/", new[] { ("cookie", "a=1; _sfp=sess-1; b=2") }, https: true);
        Assert.Null(r.Header("set-cookie"));
        var r2 = h.Call("GET", "/", https: true);
        Assert.Contains("; Secure", r2.Header("set-cookie"));
        var r3 = h.Call("GET", "/", new[] { ("x-forwarded-proto", "https") });
        Assert.Contains("; Secure", r3.Header("set-cookie"));
        var ev = h.Events()[0];
        Assert.Equal("sess-1", ev.S("sid"));
        Assert.Equal(0, ev.I("ns"));
    }

    [Fact]
    public void KeepsTheAppsOwnCookies()
    {
        using var h = new Host(new FakeAnalyst(), handler: EngineFx.Respond(200, new[] { ("set-cookie", "app=1; Path=/"), ("set-cookie", "b=2") }, ""));
        var cookies = h.Call("GET", "/").HeadersNamed("set-cookie");
        Assert.Equal(3, cookies.Count);
        Assert.Contains("app=1; Path=/", cookies);
        Assert.Contains("b=2", cookies);
        Assert.Contains(cookies, c => c.StartsWith("_sfp=", StringComparison.Ordinal));
    }

    [Fact]
    public void HonoursExcludeAndSampleAndNeverCapturesCredentials()
    {
        var a = new FakeAnalyst();
        a.Config["exclude"] = new[] { "/health" };
        using var h = new Host(a);
        h.Call("GET", "/health/live");
        h.Call("GET", "/api", new[] { ("authorization", "Bearer very-secret"), ("cookie", "s=1; t=2") });
        var evs = h.Events();
        var ev = Assert.Single(evs);
        Assert.Equal("/api", ev.S("p"));
        Assert.Equal("Bearer", ev.S("auth"));
        Assert.Equal(2, ev.I("ck"));
        Assert.DoesNotContain("very-secret", evs.Json());
        Assert.DoesNotContain("s=1", evs.Json());
        a.Config["sample"] = 0;
        h.Engine.Snap!.Refresh();
        h.Call("GET", "/api");
        Assert.Single(h.Events());
    }

    [Fact]
    public void ExposesRidSidIpToTheApp()
    {
        using var h = new Host(new FakeAnalyst());
        var r = h.Call("GET", "/");
        var ctx = EngineFx.Ctx(h.Seen[0]);
        Assert.Equal(r.Header("x-rid"), ctx.Rid);
        Assert.Equal(Hosts.Peer, ctx.Ip);
        Assert.False(string.IsNullOrEmpty(ctx.Sid));
    }

    [Fact]
    public void AnAppExceptionShipsSt500AndPropagates()
    {
        using var h = new Host(new FakeAnalyst(), handler: _ => throw new InvalidOperationException("app bug"));
        Assert.Throws<InvalidOperationException>(() => h.Call("GET", "/crash"));
        var ev = Assert.Single(h.Events());
        Assert.Equal("/crash", ev.S("p"));
        Assert.Equal(500, ev.I("st"));
    }

    [Fact]
    public void TheRoutePatternReachesTheEventWhenTheHostSetsIt()
    {
        using var h = new Host(new FakeAnalyst(), handler: ctx =>
        {
            ctx.SetEndpoint(new Microsoft.AspNetCore.Routing.RouteEndpoint(_ => Task.CompletedTask, Microsoft.AspNetCore.Routing.Patterns.RoutePatternFactory.Parse("/items/{id}"), 0, null, null));
            return Hosts.Hello(ctx);
        });
        h.Call("GET", "/items/7");
        Assert.Equal("/items/{id}", h.Events()[0].S("rt"));
    }
}

public class TrackTests
{
    [Fact]
    public void TrackShipsAnAppContextEventWithAHashedUid()
    {
        Host? h = null;
        h = new Host(new FakeAnalyst(), handler: ctx =>
        {
            h!.Engine.Track(EngineFx.Ctx(ctx), "login_failed", "alice@example.com");
            ctx.Response.StatusCode = 401;
            return Task.CompletedTask;
        });
        using (h)
        {
            var r = h.Call("POST", "/login", body: "x=1"u8.ToArray());
            var evs = h.Events();
            var tracked = evs.First(e => e.ContainsKey("et"));
            Assert.Equal("login_failed", tracked.S("et"));
            Assert.Equal("sdk-dotnet", tracked.S("tap"));
            Assert.Equal(r.Header("x-rid"), tracked.S("rid"));
            var expected = Convert.ToHexString(HMACSHA256.HashData("tok-test"u8.ToArray(), "uid:alice@example.com"u8.ToArray())).ToLowerInvariant()[..32];
            Assert.Equal(expected, tracked.S("uid"));
            Assert.DoesNotContain("alice", evs.Json());
            Assert.Equal(Hosts.Peer, tracked.S("ip"));
            Assert.False(tracked.ContainsKey("p"));
        }
    }

    [Fact]
    public void TrackWithoutAUserAndWithoutContext()
    {
        using var h = new Host(new FakeAnalyst());
        h.Engine.Track(null, "signup");
        var ev = Assert.Single(h.Events());
        Assert.Equal("signup", ev.S("et"));
        Assert.True(ev.IsNull("uid"));
        Assert.True(ev.IsNull("rid"));
    }
}

public class BeaconEndpointTests
{
    [Fact]
    public void ServesTheScriptAndBatchesFpAsASigRowWithTheResolvedIp()
    {
        var a = new FakeAnalyst();
        EngineFx.Hops1(a);
        using var h = new Host(a);
        var js = h.Call("GET", "/_cam/b.js");
        Assert.Equal(200, js.Status);
        Assert.Equal("application/javascript", js.Header("content-type"));
        Assert.Contains("@camada/browser", js.Text);
        Assert.Equal("public, max-age=3600", js.Header("cache-control"));
        var body = Encoding.UTF8.GetBytes("""{"sdk":"@camada/browser/0.2.0","rid":"r-1","ip":"9.9.9.9","tap":"proxy","scr":"1x1"}""");
        var fp = h.Call("POST", "/_cam/fp", new[] { ("x-forwarded-for", "198.18.0.5"), ("content-type", "application/json") }, body);
        Assert.Equal(204, fp.Status);
        Assert.Equal("no-store", fp.Header("cache-control"));
        Assert.Empty(h.Seen);
        var row = Assert.Single(h.Events());
        Assert.Equal(1, row.I("sig"));
        Assert.Equal("198.18.0.5", row.S("ip"));
        Assert.Equal("sdk-dotnet", row.S("tap"));
        Assert.Equal("1x1", row.S("scr"));
        Assert.Equal("r-1", row.S("rid"));
    }

    [Fact]
    public void DropsJunkBodiesInsteadOfShippingThem()
    {
        using var h = new Host(new FakeAnalyst());
        foreach (var junk in new[] { "not json", "[1,2]", "42", "" })
        {
            Assert.Equal(204, h.Call("POST", "/_cam/fp", body: Encoding.UTF8.GetBytes(junk)).Status);
        }
        Assert.Empty(h.Events());
    }

    [Fact]
    public void RejectsOversizedPostsDeclaredOrActual()
    {
        using var h = new Host(new FakeAnalyst());
        Assert.Equal(413, h.Call("POST", "/_cam/fp", body: "{}"u8.ToArray(), contentLength: 40000).Status);
        Assert.Equal(413, h.Call("POST", "/_cam/fp", body: Encoding.UTF8.GetBytes("{" + new string(' ', 33000) + "}")).Status);
        Assert.Empty(h.Events());
    }

    [Fact]
    public void FallsThroughToTheAppWhenTheTenantDisabledTheBeacon()
    {
        var a = new FakeAnalyst();
        a.Config["beacon"] = false;
        using var h = new Host(a);
        Assert.Equal("hello", h.Call("GET", "/_cam/b.js").Text);
        Assert.Equal("hello", h.Call("POST", "/_cam/fp", body: "{}"u8.ToArray()).Text);
        Assert.Equal("", h.Engine.ScriptTag(EngineFx.Ctx(h.Seen[0])));
    }

    [Fact]
    public void ScriptTagCarriesTheRid()
    {
        using var h = new Host(new FakeAnalyst());
        var r = h.Call("GET", "/");
        Assert.Equal($"<script src=\"/_cam/b.js?r={r.Header("x-rid")}\" async></script>", h.Engine.ScriptTag(EngineFx.Ctx(h.Seen[0])));
        Assert.Equal("<script src=\"/_cam/b.js\" async></script>", h.Engine.ScriptTag(null));
    }

    [Fact]
    public void EnforcementComesBeforeTheBeaconEndpoints()
    {
        using var h = new Host(new FakeAnalyst());
        Assert.Equal(403, h.Call("GET", "/_cam/b.js", peer: FakeAnalyst.BlockedIp).Status);
    }
}

public class RulesTests
{
    private static FakeAnalyst V5()
    {
        var a = new FakeAnalyst { Container = "v5" };
        EngineFx.Hops1(a);
        return a;
    }

    [Fact]
    public void SkipRuleBeatsTheWiderBlock()
    {
        using var h = new Host(V5());
        Assert.Equal(200, h.Call("GET", FakeAnalyst.SkipPath, EngineFx.Ip(FakeAnalyst.BlockedIp)).Status);
        var ev = Assert.Single(h.Events());
        Assert.False(ev.ContainsKey("blk"));
        Assert.False(ev.ContainsKey("wrn"));
    }

    [Fact]
    public void BlocksByRuleWithXBlockRuleAndShipsRl()
    {
        using var h = new Host(V5());
        var r = h.Call("GET", "/", EngineFx.Ip(FakeAnalyst.RuleBlockedIp));
        Assert.Equal(403, r.Status);
        Assert.Equal("rule", r.Header("x-block-reason"));
        Assert.Equal("builtin:block", r.Header("x-block-rule"));
        var ev = Assert.Single(h.Events());
        Assert.Equal("rule", ev.S("blk"));
        Assert.Equal("builtin:block", ev.S("rl"));
    }

    [Fact]
    public void BlocksByPathUaAndHeaderRules()
    {
        using var h = new Host(V5());
        Assert.Equal("cr_00000000000c", h.Call("GET", FakeAnalyst.RuleBlockedPath).Header("x-block-rule"));
        Assert.Equal(403, h.Call("GET", "/", new[] { ("user-agent", FakeAnalyst.BlockedUa) }).Status);
        Assert.Equal(403, h.Call("GET", "/", new[] { (FakeAnalyst.BlockedHeader.ToUpperInvariant(), FakeAnalyst.BlockedHeaderValue) }).Status);   // any spelling
        Assert.Equal(200, h.Call("GET", "/", new[] { (FakeAnalyst.BlockedHeader, "other") }).Status);
        Assert.Equal(200, h.Call("GET", "/").Status);
    }

    [Fact]
    public void WarnPassesAndStampsWrn()
    {
        using var h = new Host(V5());
        Assert.Equal(200, h.Call("GET", "/", new[] { ("user-agent", FakeAnalyst.WarnUa) }).Status);
        var ev = Assert.Single(h.Events());
        Assert.Equal("cr_00000000000e", ev.S("wrn"));
        Assert.Equal(200, ev.I("st"));
    }

    [Fact]
    public void StillEnforcesAgainstAnAnalystThatOnlyPublishesV3()
    {
        var a = V5();
        a.Container = "v3";
        using var h = new Host(a);
        Assert.Equal(403, h.Call("GET", "/", EngineFx.Ip(FakeAnalyst.BlockedIp)).Status);
        Assert.Equal(200, h.Call("GET", "/", new[] { ("user-agent", FakeAnalyst.BlockedUa) }).Status);   // a rule-only signal: v3 carries no rules
    }
}

public class ChallengeFlowTests
{
    private static FakeAnalyst V4() => new() { Container = "v4" };
    private static readonly (string, string)[] Form = { ("content-type", "application/x-www-form-urlencoded") };

    [Fact]
    public void ServesThePageForAnHtmlNavigationAndShipsBlkChallenge()
    {
        using var h = new Host(V4());
        var r = h.Call("GET", "/account?tab=1", EngineFx.Html, peer: FakeAnalyst.ChallengedIp);
        Assert.Equal(403, r.Status);
        Assert.Equal("text/html; charset=utf-8", r.Header("content-type"));
        Assert.Equal("1", r.Header("x-camada-challenge"));
        Assert.Equal("no-store", r.Header("cache-control"));
        Assert.Contains("action=\"/__camada/challenge\"", r.Text);
        Assert.Contains("name=\"to\" value=\"/account?tab=1\"", r.Text);
        Assert.Empty(h.Seen);
        var ev = Assert.Single(h.Events());
        Assert.Equal(403, ev.I("st"));
        Assert.Equal("challenge", ev.S("blk"));
        Assert.Equal("/account", ev.S("p"));
    }

    [Fact]
    public void AnswersJsonForANonHtmlRequest()
    {
        using var h = new Host(V4());
        var r = h.Call("GET", "/api", new[] { ("accept", "application/json") }, peer: FakeAnalyst.ChallengedIp);
        Assert.Equal(403, r.Status);
        Assert.Equal("application/json", r.Header("content-type"));
        Assert.Equal("challenge_required", JsonDocument.Parse(r.Text).RootElement.GetProperty("error").GetString());
        var r2 = h.Call("GET", "/api", new[] { ("accept", "text/html"), ("sec-fetch-dest", "empty") }, peer: FakeAnalyst.ChallengedIp);
        Assert.Equal("application/json", r2.Header("content-type"));
    }

    [Fact]
    public void BlocksOutrightRatherThanChallengingABlockedIp()
    {
        using var h = new Host(V4());
        var r = h.Call("GET", "/", EngineFx.Html, peer: FakeAnalyst.BlockedIp);
        Assert.Equal(403, r.Status);
        Assert.Null(r.Header("x-camada-challenge"));
    }

    [Fact]
    public void VerifySetsCchRedirectsBackAndShipsCh1()
    {
        using var h = new Host(V4());
        var page = h.Call("GET", "/back?x=1", EngineFx.Html, peer: FakeAnalyst.ChallengedIp).Text;
        var nonce = EngineFx.Nonce(page);
        var form = $"nonce={nonce}&solution={Solver.Solve(nonce)}&to=%2Fback%3Fx%3D1";
        var r = h.Call("POST", "/__camada/challenge", Form, Encoding.UTF8.GetBytes(form), peer: FakeAnalyst.ChallengedIp);
        Assert.Equal(302, r.Status);
        Assert.Equal("/back?x=1", r.Header("location"));
        Assert.Equal("no-store", r.Header("cache-control"));
        var cookie = r.Header("set-cookie") ?? "";
        Assert.StartsWith("_cch=", cookie);
        Assert.Contains("HttpOnly", cookie);
        var evs = h.Events();
        Assert.Equal(200, evs[^1].I("st"));
        Assert.Equal(1, evs[^1].I("ch"));
        Assert.Equal("/__camada/challenge", evs[^1].S("p"));
        // the holder of a valid _cch passes; a cookie minted for another ip does not
        var pair = cookie.Split(';')[0];
        Assert.Equal(200, h.Call("GET", "/back", EngineFx.Html.Append(("cookie", pair)).ToArray(), peer: FakeAnalyst.ChallengedIp).Status);
        Assert.Equal(200, h.Call("GET", "/back", EngineFx.Html.Append(("cookie", pair)).ToArray(), peer: "192.0.2.21").Status);   // not challenged at all
        // a tampered mac: flip the last hex digit (replacing the first '0' threw on the values that had none)
        var forged = pair[..^1] + (pair[^1] != '0' ? "0" : "1");
        Assert.Equal(403, h.Call("GET", "/back", EngineFx.Html.Append(("cookie", forged)).ToArray(), peer: FakeAnalyst.ChallengedIp).Status);
    }

    [Fact]
    public void WrongSolutionOrForgedNonceServesThePageAgain()
    {
        using var h = new Host(V4());
        var nonce = EngineFx.Nonce(h.Call("GET", "/", EngineFx.Html, peer: FakeAnalyst.ChallengedIp).Text);
        var r = h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes($"nonce={nonce}&solution=1&to=%2F"), peer: FakeAnalyst.ChallengedIp);
        Assert.Equal(403, r.Status);
        Assert.Null(r.Header("set-cookie"));
        Assert.Contains("camada-f", r.Text);
        var forged = new string('f', 32);
        r = h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes($"nonce={forged}&solution={Solver.Solve(forged)}&to=%2F"), peer: FakeAnalyst.ChallengedIp);
        Assert.Equal(403, r.Status);
        Assert.Null(r.Header("set-cookie"));
    }

    [Fact]
    public void NeverRedirectsOffSite()
    {
        using var h = new Host(V4());
        var nonce = h.Engine.Kit!.Nonce(FakeAnalyst.ChallengedIp, h.Engine.NowMs());
        var r = h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes($"nonce={nonce}&solution={Solver.Solve(nonce)}&to=https%3A%2F%2Fevil"), peer: FakeAnalyst.ChallengedIp);
        Assert.Equal(302, r.Status);
        Assert.Equal("/", r.Header("location"));
    }

    [Fact]
    public void RefusesAnOversizedVerifyBody()
    {
        using var h = new Host(V4());
        Assert.Equal(413, h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes("a=" + new string('b', 5000)), peer: FakeAnalyst.ChallengedIp).Status);
    }

    [Fact]
    public void NoIpMeansNoChallenge()
    {
        using var h = new Host(V4());
        Assert.Equal(200, h.Call("GET", "/", EngineFx.Html, peer: null).Status);
    }

    [Fact]
    public void SwitchedOffByEnvOrOption()
    {
        using var h1 = new Host(V4(), new() { ["CAMADA_CHALLENGE"] = "0" });
        Assert.Equal(200, h1.Call("GET", "/", EngineFx.Html, peer: FakeAnalyst.ChallengedIp).Status);
        using var h2 = new Host(V4(), configure: o => o.Challenge = false);
        Assert.Equal(200, h2.Call("GET", "/", EngineFx.Html, peer: FakeAnalyst.ChallengedIp).Status);
    }

    [Fact]
    public void ServeChallengeOnDemand()
    {
        Host? h = null;
        h = new Host(V4(), handler: async ctx =>
        {
            var answer = h!.Engine.ServeChallenge(EngineFx.Ctx(ctx));
            if (answer != null)
            {
                ctx.Response.StatusCode = answer.Status;
                foreach (var (k, v) in answer.Headers)
                {
                    ctx.Response.Headers.Append(k, v);
                }
                await ctx.Response.Body.WriteAsync(answer.Body);
                return;
            }
            await ctx.Response.Body.WriteAsync("secret page"u8.ToArray());
        });
        using (h)
        {
            var r = h.Call("GET", "/challenge-me", EngineFx.Html);
            Assert.Equal(403, r.Status);
            Assert.Contains("camada-f", r.Text);
            var evs = h.Events();
            Assert.Single(evs);
            Assert.Equal("challenge", evs[0].S("blk"));   // one request, one event
            var nonce = EngineFx.Nonce(r.Text);
            var ok = h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes($"nonce={nonce}&solution={Solver.Solve(nonce)}&to=%2Fchallenge-me"));
            var cookie = (ok.Header("set-cookie") ?? "").Split(';')[0];
            Assert.Equal("secret page", h.Call("GET", "/challenge-me", EngineFx.Html.Append(("cookie", cookie)).ToArray()).Text);
        }
    }
}

public class FailOpenTests
{
    [Fact]
    public void KeepsServingWhenIngestIsDown()
    {
        using var h = new Host(new FakeAnalyst { IngestDown = true });
        Assert.Equal(200, h.Call("GET", "/").Status);
        Assert.Empty(h.Events());
        Assert.Equal(1, h.Engine.Queue!.Dropped);
    }

    [Fact]
    public void DisabledBypassesTheSdkEntirely()
    {
        var a = new FakeAnalyst();
        using var h = new Host(a, new() { ["CAMADA_DISABLED"] = "1" }, load: false);
        Assert.Null(h.Engine.Snap);
        Assert.True(h.Engine.Disabled);
        var r = h.Call("GET", "/", peer: FakeAnalyst.BlockedIp);
        Assert.Equal(200, r.Status);
        Assert.Null(r.Header("x-rid"));
        Assert.Empty(a.SnapshotRequests);
        Assert.Null(h.Engine.WantsBody("POST", "/_cam/fp"));
    }

    [Fact]
    public void TheKillSwitchIsReadPerRequest()
    {
        var env = new Dictionary<string, string?>(Hosts.Env);
        using var h = new Host(new FakeAnalyst(), configure: o => o.Env = env);   // the live map, read per request like the process environment
        Assert.Equal(403, h.Call("GET", "/", peer: FakeAnalyst.BlockedIp).Status);
        env["CAMADA_DISABLED"] = "1";   // flipped at runtime: the next request bypasses the SDK
        var r = h.Call("GET", "/", peer: FakeAnalyst.BlockedIp);
        Assert.Equal(200, r.Status);
        Assert.Null(r.Header("x-rid"));
        Assert.Equal("", h.Engine.ScriptTag(null));
    }

    [Fact]
    public void StaysInertWithoutCredentials()
    {
        using var h = new Host(new FakeAnalyst(), new() { ["CAMADA_KEY"] = "" }, load: false);
        Assert.Null(h.Engine.Env);
        Assert.Equal(200, h.Call("GET", "/", peer: FakeAnalyst.BlockedIp).Status);
        Assert.Equal("", h.Engine.ScriptTag(null));
        Assert.Null(h.Engine.ServeChallenge(null));
        h.Engine.Track(null, "x");
    }

    [Fact]
    public void ACamadaBugCostsTheJoinNotTheRequest()
    {
        using var h = new Host(new FakeAnalyst());
        h.Engine.DecideHook = (_, _) => throw new InvalidOperationException("sdk bug");
        var r = h.Call("GET", "/", peer: FakeAnalyst.BlockedIp);
        Assert.Equal(200, r.Status);
        Assert.Equal("hello", r.Text);
        Assert.Null(r.Header("x-rid"));
    }

    [Fact]
    public void TheReadmeWarmUpWaitsForTheBootPoll()
    {
        // The README's startup recipe: the engine build has already kicked the boot poll; waiting on Verdict()
        // until it is not cold is the bounded warm-up (a synchronous Refresh() would wait behind that poll and
        // then poll once more, on the network, before the app can start).
        var a = new FakeAnalyst();
        var engine = Hosts.EngineWith(a);
        try
        {
            Assert.NotNull(engine.Snap);
            Hosts.WaitUntil(() => engine.Snap!.Verdict(new Snapshot.MatchInput { Ip = "0.0.0.0" }).Reason != "cold", ms: 5000);
            Assert.True(engine.Snap!.Verdict(new Snapshot.MatchInput { Ip = FakeAnalyst.BlockedIp }).Block);
        }
        finally
        {
            engine.Stop();
        }
    }
}

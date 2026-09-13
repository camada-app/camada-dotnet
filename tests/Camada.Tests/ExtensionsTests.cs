// The two-line install: `builder.Services.AddCamada(); app.UseCamada();` plus the HttpContext
// helpers (CamadaScriptTag, CamadaTrack, CamadaServeChallenge), wired through a real
// IApplicationBuilder over a ServiceCollection, and the lazy default engine.
using System.Net;
using System.Text;
using Camada.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Camada.Tests;

public class ExtensionsTests : IDisposable
{
    private readonly FakeAnalyst _a = new();
    private CamadaEngine? _engine;

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public readonly CancellationTokenSource Stopping = new();
        public readonly CancellationTokenSource Stopped = new();
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => Stopping.Token;
        public CancellationToken ApplicationStopped => Stopped.Token;
        public void StopApplication() => Stopping.Cancel();
    }

    private (RequestDelegate App, IServiceProvider Services, Lifetime Lifetime) Build(Func<HttpContext, Task> handler, Dictionary<string, string?>? env = null, Action<CamadaOptions>? configure = null)
    {
        var services = new ServiceCollection();
        var lifetime = new Lifetime();
        services.AddSingleton<IHostApplicationLifetime>(lifetime);
        var merged = new Dictionary<string, string?>(Hosts.Env) { ["CAMADA_TRUSTED_PROXY"] = "hops:1" };
        foreach (var (k, v) in env ?? new())
        {
            merged[k] = v;
        }
        services.AddCamada(o =>
        {
            o.Env = merged;
            o.Transport = _a.Transport;
            configure?.Invoke(o);
        });
        var sp = services.BuildServiceProvider();
        var app = new ApplicationBuilder(sp);
        app.UseCamada();
        app.Run(ctx => handler(ctx));
        _engine = sp.GetRequiredService<CamadaEngine>();
        Hosts.Loaded(_engine);
        return (app.Build(), sp, lifetime);
    }

    private static async Task<(int Status, string Body, IHeaderDictionary Headers)> Run(RequestDelegate app, IServiceProvider sp, string path, params (string, string)[] headers)
    {
        var ctx = new DefaultHttpContext { RequestServices = sp };
        var rf = new RecordingResponseFeature();
        ctx.Features.Set<IHttpResponseFeature>(rf);
        ctx.Request.Method = "GET";
        ctx.Request.Path = path;
        ctx.Request.Headers.Host = "x.test";
        foreach (var (k, v) in headers)
        {
            ctx.Request.Headers.Append(k, v);
        }
        ctx.Connection.RemoteIpAddress = IPAddress.Loopback;
        var body = new MemoryStream();
        ctx.Response.Body = body;
        await app(ctx);
        await rf.StartAsync();
        return (ctx.Response.StatusCode, Encoding.UTF8.GetString(body.ToArray()), ctx.Response.Headers);
    }

    [Fact]
    public async Task BlocksCapturesAndTracksThroughTheRegisteredEngine()
    {
        var (app, sp, _) = Build(async ctx =>
        {
            ctx.CamadaTrack("signup", "alice@example.com");
            await ctx.Response.WriteAsync("<html>" + ctx.CamadaScriptTag() + "</html>");
        });
        var blocked = await Run(app, sp, "/", ("x-forwarded-for", FakeAnalyst.BlockedIp));
        Assert.Equal(403, blocked.Status);
        var ok = await Run(app, sp, "/", ("x-forwarded-for", "172.16.0.9"));
        Assert.Equal(200, ok.Status);
        Assert.Contains($"?r={ok.Headers["x-rid"]}", ok.Body);
        Assert.StartsWith("_sfp=", ok.Headers["set-cookie"].ToString());
        _engine!.Queue!.Flush();
        var evs = _a.AllEvents;
        Assert.Equal(new long?[] { 403, 200 }, evs.Where(e => e.ContainsKey("p")).Select(e => e.I("st")));
        var tracked = evs.First(e => e.ContainsKey("et"));
        Assert.Equal("signup", tracked.S("et"));
        Assert.Equal(ok.Headers["x-rid"].ToString(), tracked.S("rid"));
        Assert.DoesNotContain("alice", evs.Json());
    }

    [Fact]
    public async Task ARouteGatesItselfWithCamadaServeChallenge()
    {
        var (app, sp, _) = Build(async ctx =>
        {
            var challenge = ctx.CamadaServeChallenge();
            if (challenge != null)
            {
                await challenge.ExecuteAsync(ctx);
                return;
            }
            await ctx.Response.WriteAsync("file");
        });
        var html = new[] { ("x-forwarded-for", "172.16.0.9"), ("accept", "text/html"), ("sec-fetch-dest", "document") };
        var r = await Run(app, sp, "/export", html);
        Assert.Equal(403, r.Status);
        Assert.Equal("1", r.Headers["x-camada-challenge"]);
        Assert.StartsWith("text/html", r.Headers["content-type"].ToString());
        var cch = _engine!.Kit!.Issue("172.16.0.9", _engine.NowMs());
        var passed = await Run(app, sp, "/export", html.Append(("cookie", $"_cch={cch}")).ToArray());
        Assert.Equal("file", passed.Body);
        _engine.Queue!.Flush();
        Assert.Equal(new[] { (403L, "challenge"), (200L, (string?)null) }, _a.AllEvents.Select(e => (e.I("st")!.Value, e.S("blk"))));   // one request, one event
    }

    [Fact]
    public async Task TheHelpersStandDownWithoutTheMiddleware()
    {
        var ctx = new DefaultHttpContext();   // no RequestServices, no camada item: the process default engine, inert here
        CamadaEngine.ResetDefaultForTests(new CamadaOptions { Env = new Dictionary<string, string?>() });
        try
        {
            Assert.Equal("", ctx.CamadaScriptTag());
            Assert.Null(ctx.CamadaServeChallenge());
            ctx.CamadaTrack("login_failed", "bob");
            var body = new MemoryStream();
            ctx.Response.Body = body;
            await new CamadaMiddleware(Hosts.Hello, (IServiceProvider?)null).InvokeAsync(ctx);   // the default engine is what an unregistered middleware uses
            Assert.Equal("hello", Encoding.UTF8.GetString(body.ToArray()));
            Assert.Null(_a.SnapshotRequests.SingleOrDefault());
        }
        finally
        {
            CamadaEngine.ResetDefaultForTests(null);
        }
    }

    [Fact]
    public void TheDefaultEngineIsBuiltOnceFromTheProcessEnvironmentAndConfigureReplacesIt()
    {
        CamadaEngine.ResetDefaultForTests(null);
        try
        {
            Environment.SetEnvironmentVariable("CAMADA_DISABLED", "1");
            Environment.SetEnvironmentVariable("CAMADA_KEY", "a.b");
            var d = CamadaEngine.Default;
            Assert.Same(d, CamadaEngine.Default);
            Assert.True(d.Disabled);
            Assert.Null(d.Snap);   // killed at boot: no loop, no requests
            var replaced = CamadaEngine.Configure(new CamadaOptions { Env = Hosts.Env, Transport = _a.Transport });
            Assert.Same(replaced, CamadaEngine.Default);
            Assert.NotSame(d, replaced);
            Assert.NotNull(replaced.Snap);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CAMADA_DISABLED", null);
            Environment.SetEnvironmentVariable("CAMADA_KEY", null);
            CamadaEngine.ResetDefaultForTests(null);
        }
    }

    [Fact]
    public async Task ApplicationStoppingDrainsThePendingBatch()
    {
        var (app, sp, lifetime) = Build(Hosts.Hello);
        await Run(app, sp, "/", ("x-forwarded-for", "172.16.0.9"));
        Assert.Empty(_a.Events);
        lifetime.StopApplication();   // the host's ApplicationStopping: Drain(0.5 s), no signal handlers of our own
        Assert.Single(_a.Events);
    }

    [Fact]
    public void ApplicationStoppedEndsThePollLoop()
    {
        // a host built and disposed in-process (a WebApplicationFactory per test) must not leave its poller behind
        var (_, _, lifetime) = Build(Hosts.Hello, configure: o => o.RefreshS = 0.02);
        Hosts.WaitUntil(() => _a.SnapshotRequests.Count >= 3);
        Assert.True(_a.SnapshotRequests.Count >= 3);
        lifetime.Stopped.Cancel();
        Thread.Sleep(50);   // a tick already past the timer finishes its poll
        var n = _a.SnapshotRequests.Count;
        Thread.Sleep(100);   // five periods: a live poller would have polled again
        Assert.Equal(n, _a.SnapshotRequests.Count);
    }

    public void Dispose() => _engine?.Stop();
}

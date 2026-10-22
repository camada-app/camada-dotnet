// What only the ASP.NET Core host can show: the HttpContext mapping, a body camada read being
// replayed to the app, the OnStarting stamp, and OnFinish firing exactly once.
using System.Net;
using System.Net.Sockets;
using System.Text;
using Camada.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;

namespace Camada.Tests;

[Collection(SerialCollection.Name)] // real Kestrel serves on the pool the parallel tests keep busy
public class MiddlewareTests
{
    [Fact]
    public void HttpContextMapping()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "PUT";
        ctx.Request.Path = "/a";
        ctx.Request.QueryString = new QueryString("?x=1");
        ctx.Request.Protocol = "HTTP/1.0";
        ctx.Request.Scheme = "https";
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:1.2.3.4");
        ctx.Request.Headers.Host = "h:8080";
        ctx.Request.Headers.Append("X-Forwarded-For", "5.6.7.8");
        ctx.Request.Headers.Append("Cookie", "a=1");
        ctx.Request.Headers.Append("Cookie", "b=2");
        ctx.Request.ContentType = "text/plain";
        ctx.Request.ContentLength = 3;
        var req = CamadaMiddleware.ReqOf(ctx);
        Assert.Equal(("PUT", "/a", "?x=1", "h:8080", "1.0", "1.2.3.4", true), (req.Method, req.Path, req.Query, req.Host, req.HttpVersion, req.Peer, req.Https));
        Assert.Contains(new KeyValuePair<string, string>("x-forwarded-for", "5.6.7.8"), req.Headers);
        Assert.Contains(new KeyValuePair<string, string>("content-type", "text/plain"), req.Headers);
        Assert.Contains(new KeyValuePair<string, string>("content-length", "3"), req.Headers);
        Assert.Equal("5.6.7.8", req.Header("x-forwarded-for"));
        Assert.Equal("a=1; b=2", req.Header("cookie"));   // repeated cookie fields join the way node:http joins them
        Assert.Null(req.Header("x-nope"));
    }

    // C6 v3 adapter row (dotnet): RemoteIpAddress is the peer; null on a TCP listener = unreadable (no client ip,
    // never the XFF walk); a unix-socket listener has no peer, so cidrs walks X-Forwarded-For alone.
    [Theory]
    [InlineData(false, "172.64.1.1", "198.51.100.9")]            // through the edge
    [InlineData(false, "::ffff:203.0.113.200", "203.0.113.200")]  // a direct hit: the peer
    [InlineData(false, null, null)]                                // unreadable on TCP
    [InlineData(true, null, "198.51.100.9")]                       // UnixSocketListener: the walk
    public void PeerIsRemoteIpAddressAndAnUnreadableOneNeverWalksXff(bool unix, string? peer, string? ip)
    {
        var a = new FakeAnalyst();
        using var h = new Host(a, env: new() { ["CAMADA_TRUSTED_PROXY"] = "cidrs:172.64.0.0/13" }, configure: o => o.UnixSocketListener = unix);
        h.Call(headers: new[] { ("X-Forwarded-For", "1.2.3.4, 198.51.100.9, 172.64.1.1") }, peer: peer);
        var evs = h.Events();
        Assert.Equal(ip, evs[^1]["ip"].ValueKind == System.Text.Json.JsonValueKind.Null ? null : evs[^1]["ip"].GetString());
    }

    // camada-all-0vho RB-1: a real Kestrel ListenUnixSocket listener (.NET 8) exposes no IConnectionEndPointFeature and
    // leaves LocalIpAddress/RemoteIpAddress null, so the listener is recognised by the missing local address alone:
    // without UnixSocketListener the request must still walk X-Forwarded-For, never read as an unreadable TCP peer.
    [Fact]
    public async Task ARealKestrelUnixSocketListenerWalksXffWithoutTheOption()
    {
        if (OperatingSystem.IsWindows())
        {
            return;   // AF_UNIX on Windows Kestrel is not what this guards; the unix-socket deployments are Linux
        }
        var sock = Path.Combine(Path.GetTempPath(), $"camada-{Guid.NewGuid():N}.sock"[..32]);
        var a = new FakeAnalyst();
        using var engine = new EngineHandle(Hosts.EngineWith(a, new() { ["CAMADA_TRUSTED_PROXY"] = "cidrs:172.64.0.0/13" }));
        Hosts.Loaded(engine.E);
        var b = WebApplication.CreateSlimBuilder();
        b.Logging.ClearProviders();
        b.WebHost.ConfigureKestrel(k => k.ListenUnixSocket(sock));
        await using var app = b.Build();
        app.Use(next => new CamadaMiddleware(next, engine.E).InvokeAsync);
        app.Run(Hosts.Hello);
        await app.StartAsync();
        try
        {
            using var http = new HttpClient(new SocketsHttpHandler
            {
                ConnectCallback = async (_, ct) =>
                {
                    var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    await s.ConnectAsync(new UnixDomainSocketEndPoint(sock), ct);
                    return new NetworkStream(s, ownsSocket: true);
                },
            });
            using var msg = new HttpRequestMessage(HttpMethod.Get, "http://x.test/");
            msg.Headers.TryAddWithoutValidation("X-Forwarded-For", "1.2.3.4, 198.51.100.9, 172.64.1.1");
            using var r = await http.SendAsync(msg);   // 198.51.100.9 may be blocked by the container: only the ip matters
            List<Dictionary<string, System.Text.Json.JsonElement>> evs = new();
            Hosts.WaitUntil(() => { engine.E.Queue!.Flush(); evs = a.AllEvents; return evs.Count > 0; });
            Assert.Equal("198.51.100.9", Assert.Single(evs).S("ip"));
        }
        finally
        {
            await app.StopAsync();
            File.Delete(sock);
        }
    }

    [Fact]
    public void ANullRemoteIpOnATcpListenerIsUnreadable()
    {
        var tcp = new DefaultHttpContext();   // a TCP listener always sets LocalIpAddress
        tcp.Connection.LocalIpAddress = IPAddress.Loopback;
        Assert.Null(CamadaMiddleware.ReqOf(tcp).Peer);
        Assert.True(CamadaMiddleware.ReqOf(tcp).PeerUnreadable);
        var socket = CamadaMiddleware.ReqOf(new DefaultHttpContext());   // no local address: a unix socket or named pipe
        Assert.Null(socket.Peer);
        Assert.False(socket.PeerUnreadable);
        var configured = CamadaMiddleware.ReqOf(tcp, unixSocketListener: true);
        Assert.False(configured.PeerUnreadable);
    }

    // camada-all-8lp6: a middleware ahead of camada marks every response public; the per-visitor block 403 must
    // go out with only no-store, or a shared cache serves it to the next visitor
    [Fact]
    public async Task ABlockReplacesACacheControlSetBeforeIt()
    {
        using var engine = new EngineHandle(Hosts.EngineWith(new FakeAnalyst()));
        Hosts.Loaded(engine.E);
        var ran = false;
        var mw = new CamadaMiddleware(_ => { ran = true; return Task.CompletedTask; }, engine.E);
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(FakeAnalyst.BlockedIp);
        ctx.Response.Headers.CacheControl = "public, max-age=600";
        await mw.InvokeAsync(ctx);
        Assert.False(ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Equal(new[] { "no-store" }, ctx.Response.Headers.CacheControl.ToArray());
    }

    private sealed class EngineHandle : IDisposable
    {
        public EngineHandle(CamadaEngine e) => E = e;

        public CamadaEngine E { get; }

        public void Dispose() => E.Stop();
    }

    [Fact]
    public void PathRulesSeeTheRawTargetNotTheDecodedPath()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/blocked-path";   // what Kestrel decodes /%62locked-path into
        ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!.RawTarget = "/%62locked-path?x=1";
        Assert.Equal("/%62locked-path", CamadaMiddleware.ReqOf(ctx).RawPath);

        var bare = new DefaultHttpContext();   // no origin-form target: PathBase + Path
        bare.Request.PathBase = "/app";
        bare.Request.Path = "/a";
        bare.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!.RawTarget = "*";
        Assert.Equal("/app/a", CamadaMiddleware.ReqOf(bare).RawPath);
    }

    [Fact]
    public void RepeatedHeadersJoinWithACommaExceptCookie()
    {
        var req = new Req { Headers = new List<KeyValuePair<string, string>> { new("accept", "a"), new("accept", "b"), new("cookie", "x=1"), new("cookie", "y=2") } };
        Assert.Equal("a, b", req.Header("accept"));
        Assert.Equal("x=1; y=2", req.Header("cookie"));
    }

    [Fact]
    public void ABodyCamadaReadIsReplayedToTheApp()
    {
        var a = new FakeAnalyst();
        a.Config["beacon"] = false;
        var got = new List<string>();
        using var h = new Host(a, handler: async ctx =>
        {
            using var reader = new StreamReader(ctx.Request.Body);
            got.Add(await reader.ReadToEndAsync());
            await ctx.Response.Body.WriteAsync("ok"u8.ToArray());
        });
        // a beacon POST with the beacon off falls through: the app must still read the body
        var r = h.Call("POST", "/_cam/fp", body: "{}"u8.ToArray());
        Assert.Equal("ok", r.Text);
        Assert.Equal(new[] { "{}" }, got);
    }

    [Fact]
    public void ABodyOverTheCapReachesTheAppWhole()
    {
        // no ip -> camada never answers the verify endpoint, so the app gets the request with its full body
        var big = new string('x', 70_000);
        var got = new List<string>();
        using var h = new Host(new FakeAnalyst(), handler: async ctx =>
        {
            using var reader = new StreamReader(ctx.Request.Body);
            got.Add(await reader.ReadToEndAsync());
            await ctx.Response.Body.WriteAsync("ok"u8.ToArray());
        });
        var r = h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes(big), peer: null);
        Assert.Equal("ok", r.Text);
        Assert.Equal(new[] { big }, got);
    }

    [Fact]
    public void ABodyCamadaReadIsRewoundThroughEnableBuffering()
    {
        // The one path where camada reads a body and then runs the app: a verify POST under the cap with no
        // resolvable ip (no challenge without one). Kestrel's body cannot seek, so Request.EnableBuffering()
        // has to wrap it, and the rewind after camada's partial read runs against that wrapper.
        var form = "nonce=" + new string('n', 3000) + "&solution=1";
        var got = new List<string>();
        using var h = new Host(new FakeAnalyst(), handler: async ctx =>
        {
            using var reader = new StreamReader(ctx.Request.Body);
            got.Add(await reader.ReadToEndAsync());
            await ctx.Response.Body.WriteAsync("ok"u8.ToArray());
        });
        var r = h.Call("POST", "/__camada/challenge", body: Encoding.UTF8.GetBytes(form), peer: null, seekable: false);
        Assert.Equal("ok", r.Text);
        Assert.Equal(new[] { form }, got);
        Assert.IsType<FileBufferingReadStream>(h.Seen.Single().Request.Body);
    }

    [Fact]
    public void OnFinishFiresExactlyOnceWithTheFinalStatus()
    {
        var a = new FakeAnalyst();
        using var h = new Host(a, handler: ctx =>
        {
            ctx.Response.StatusCode = 418;
            return Task.CompletedTask;
        });
        h.Call("GET", "/tea");
        h.Call("GET", "/tea");
        var evs = h.Events();
        Assert.Equal(2, evs.Count);
        Assert.All(evs, e => Assert.Equal(418, e.I("st")));
    }

    [Fact]
    public void A101HandshakeCarriesNoRid()
    {
        using var h = new Host(new FakeAnalyst(), handler: ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status101SwitchingProtocols;   // what Kestrel's upgrade sets before it starts the response
            return Task.CompletedTask;
        });
        var r = h.Call("GET", "/ws", headers: new[] { ("Upgrade", "websocket"), ("Connection", "Upgrade") });
        Assert.Equal(101, r.Status);
        Assert.Null(r.Header("x-rid"));
        var ev = Assert.Single(h.Events());
        Assert.Equal(101, ev["st"].GetInt32());
        Assert.False(string.IsNullOrEmpty(ev["rid"].GetString()));
    }

    [Fact]
    public void TheStampRidesOnStartingSoAnAppThatClearsHeadersStillCarriesIt()
    {
        using var h = new Host(new FakeAnalyst(), handler: ctx =>
        {
            ctx.Response.Headers.Clear();
            ctx.Response.StatusCode = 200;
            return Task.CompletedTask;
        });
        var r = h.Call("GET", "/");
        Assert.NotNull(r.Header("x-rid"));
        Assert.StartsWith("_sfp=", r.Header("set-cookie"));
    }

    [Fact]
    public async Task AHostFailureBeforeTheEngineFallsThroughToTheApp()
    {
        using var h = new Host(new FakeAnalyst());
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = "/_cam/fp";
        ctx.Request.ContentLength = 2;
        ctx.Request.Body = new ThrowingStream();   // a body the host cannot read: log, run the app, never 500 from camada
        ctx.Response.Body = new MemoryStream();
        await new CamadaMiddleware(Hosts.Hello, h.Engine).InvokeAsync(ctx);
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    private sealed class ThrowingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("client went away");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

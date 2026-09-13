// What only the ASP.NET Core host can show: the HttpContext mapping, a body camada read being
// replayed to the app, the OnStarting stamp, and OnFinish firing exactly once.
using System.Net;
using System.Text;
using Camada.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace Camada.Tests;

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

// The driver that runs the SDK through the ASP.NET Core middleware without a server: a
// DefaultHttpContext per call, with a response feature that records OnStarting callbacks and
// fires them when the app is done, the way a server starts the response. The engine suite runs
// on it; middleware-specific behaviour lives in MiddlewareTests.cs.
using System.Net;
using System.Text;
using System.Text.Json;
using Camada.AspNetCore;
using Camada.Snapshot;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Camada.Tests;

public sealed record Reply(int Status, List<KeyValuePair<string, string>> Headers, byte[] Body)
{
    public string? Header(string name) => Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    public List<string> HeadersNamed(string name) => Headers.Where(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).ToList();

    public string Text => Encoding.UTF8.GetString(Body);
}

/// <summary>DefaultHttpContext's response feature drops OnStarting callbacks; a server runs them once
/// before the first byte. This one keeps them so the driver can do the same.</summary>
public sealed class RecordingResponseFeature : HttpResponseFeature
{
    private readonly List<(Func<object, Task> Cb, object State)> _starting = new();
    private bool _started;

    public override void OnStarting(Func<object, Task> callback, object state) => _starting.Add((callback, state));

    public async Task StartAsync()
    {
        if (_started)
        {
            return;
        }
        _started = true;
        for (var i = _starting.Count - 1; i >= 0; i--)   // servers run them in reverse registration order
        {
            await _starting[i].Cb(_starting[i].State);
        }
    }
}

public static class Hosts
{
    public static readonly Dictionary<string, string?> Env = new() { ["CAMADA_KEY"] = "tok-test.snap-test", ["CAMADA_INGEST_URL"] = "https://analyst.test" };
    public const string Peer = "172.16.0.9";   // a peer no golden container lists (10.0.0.0/8 is blocked in all of them)

    public static CamadaEngine EngineWith(FakeAnalyst a, Dictionary<string, string?>? env = null, Action<CamadaOptions>? configure = null)
    {
        var merged = new Dictionary<string, string?>(Env);
        foreach (var (k, v) in env ?? new())
        {
            merged[k] = v;
        }
        var opts = new CamadaOptions { Env = merged, Transport = a.Transport };
        configure?.Invoke(opts);
        return new CamadaEngine(opts);
    }

    public static void Loaded(CamadaEngine engine)
    {
        Assert.NotNull(engine.Snap);
        for (var i = 0; i < 400; i++)
        {
            if (engine.Snap!.Verdict(new MatchInput { Ip = "0.0.0.0" }).Reason != "cold")
            {
                return;
            }
            Thread.Sleep(5);
        }
        Assert.Fail("snapshot never loaded");
    }

    public static Task Hello(HttpContext ctx)
    {
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentType = "text/plain";
        return ctx.Response.Body.WriteAsync("hello"u8.ToArray()).AsTask();
    }
}

/// <summary>One engine + one host per test, loaded unless asked otherwise.</summary>
public sealed class Host : IDisposable
{
    public FakeAnalyst A { get; }
    public CamadaEngine Engine { get; }
    public List<HttpContext> Seen { get; } = new();
    private readonly RequestDelegate _app;

    public Host(FakeAnalyst a, Dictionary<string, string?>? env = null, Func<HttpContext, Task>? handler = null, bool load = true, Action<CamadaOptions>? configure = null)
    {
        A = a;
        Engine = Hosts.EngineWith(a, env, configure);
        var h = handler ?? Hosts.Hello;
        RequestDelegate app = ctx =>
        {
            Seen.Add(ctx);
            return h(ctx);
        };
        _app = new CamadaMiddleware(app, Engine).InvokeAsync;
        if (load && Engine.Snap != null)
        {
            Hosts.Loaded(Engine);
        }
    }

    public Reply Call(string method = "GET", string path = "/", (string, string)[]? headers = null, byte[]? body = null, string? peer = Hosts.Peer, bool https = false, long? contentLength = null) =>
        CallAsync(method, path, headers, body, peer, https, contentLength).GetAwaiter().GetResult();

    public async Task<Reply> CallAsync(string method = "GET", string path = "/", (string, string)[]? headers = null, byte[]? body = null, string? peer = Hosts.Peer, bool https = false, long? contentLength = null)
    {
        body ??= Array.Empty<byte>();
        var ctx = new DefaultHttpContext();
        var responseFeature = new RecordingResponseFeature();
        ctx.Features.Set<IHttpResponseFeature>(responseFeature);
        var q = path.IndexOf('?');
        ctx.Request.Method = method;
        ctx.Request.Path = q == -1 ? path : path[..q];
        ctx.Request.QueryString = q == -1 ? QueryString.Empty : new QueryString(path[q..]);
        ctx.Request.Scheme = https ? "https" : "http";
        ctx.Request.Protocol = "HTTP/1.1";
        foreach (var (k, v) in headers ?? Array.Empty<(string, string)>())
        {
            ctx.Request.Headers.Append(k, v);
        }
        if (!ctx.Request.Headers.ContainsKey("Host"))
        {
            ctx.Request.Headers.Host = "x.test";
        }
        if (method is "POST" or "PUT" || body.Length > 0)
        {
            ctx.Request.ContentLength = contentLength ?? body.Length;
        }
        ctx.Request.Body = new MemoryStream(body);
        ctx.Connection.RemoteIpAddress = peer == null ? null : IPAddress.Parse(peer);
        var outBody = new MemoryStream();
        ctx.Response.Body = outBody;
        await _app(ctx);
        await responseFeature.StartAsync();
        var hs = new List<KeyValuePair<string, string>>();
        foreach (var (k, vs) in ctx.Response.Headers)
        {
            foreach (var v in vs)
            {
                hs.Add(new(k, v ?? ""));
            }
        }
        return new Reply(ctx.Response.StatusCode, hs, outBody.ToArray());
    }

    public List<Dictionary<string, JsonElement>> Events()
    {
        Assert.NotNull(Engine.Queue);
        Engine.Queue!.Flush();
        return A.AllEvents;
    }

    public void Dispose() => Engine.Stop();
}

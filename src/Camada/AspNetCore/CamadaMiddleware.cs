// ASP.NET Core middleware: `app.UseCamada()` first in the pipeline, so camada answers before
// routing, static files or anything else runs. A Passed request runs the app with x-rid and the
// _sfp cookie stamped on the response as it starts (Response.OnStarting), the context in
// HttpContext.Items["camada"], and OnFinish(status) fired exactly once — with 500 when the app
// throws, the exception propagating unchanged.
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Camada.AspNetCore;

public sealed class CamadaMiddleware
{
    public const string ItemKey = "camada";
    // CDNs read their own cache header ahead of cache-control: a signalled response sets all of these no-store.
    internal static readonly string[] NoStoreHeaders = { "cache-control", "cdn-cache-control", "surrogate-control", "cloudflare-cdn-cache-control", "vercel-cdn-cache-control", "netlify-cdn-cache-control" };

    private readonly RequestDelegate _next;
    private readonly IServiceProvider? _services;
    private CamadaEngine? _engine;

    /// <summary>What UseCamada() builds: the engine AddCamada() registered, else the process default on first use.</summary>
    public CamadaMiddleware(RequestDelegate next, IServiceProvider? services)
    {
        _next = next;
        _services = services;
    }

    internal CamadaMiddleware(RequestDelegate next, CamadaEngine engine)
    {
        _next = next;
        _engine = engine;
    }

    private CamadaEngine Engine => _engine ??= _services?.GetService<CamadaEngine>() ?? CamadaEngine.Default;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var eng = Engine;
        Req req;
        byte[]? body = null;
        try
        {
            req = ReqOf(ctx, eng.UnixSocketListener);
            var limit = eng.WantsBody(req.Method, req.Path);
            if (limit is { } cap)
            {
                body = await ReadBody(ctx, cap).ConfigureAwait(false);
            }
        }
        catch (Exception err)
        {
            Guarded.LogRateLimited(err);
            await _next(ctx).ConfigureAwait(false);
            return;
        }
        var result = eng.Handle(req, body);
        if (result is Answer a)
        {
            await Write(ctx, a).ConfigureAwait(false);
            return;
        }
        await Run(ctx, (Passed)result).ConfigureAwait(false);
    }

    /// <summary>The engine's request from the ASP.NET Core one; the listener kind comes from the connection's local
    /// address (see the overload).</summary>
    public static Req ReqOf(HttpContext ctx) => ReqOf(ctx, false);

    /// <summary>The engine's request from the ASP.NET Core one. The peer is `RemoteIpAddress`; on a unix-socket (or
    /// named-pipe) listener there is none, so a cidrs config walks X-Forwarded-For alone; on a TCP listener a null one
    /// marks the peer unreadable (no client ip). The listener is a socket one when configured, or when the connection
    /// has neither a local nor a remote ip address: Kestrel's TCP transport always sets the local one, while its
    /// unix-socket and named-pipe transports leave both null (and expose no IConnectionEndPointFeature on .NET 8).</summary>
    public static Req ReqOf(HttpContext ctx, bool unixSocketListener)
    {
        var unix = unixSocketListener || (ctx.Connection.LocalIpAddress == null && ctx.Connection.RemoteIpAddress == null);
        var r = ctx.Request;
        var headers = new List<KeyValuePair<string, string>>();
        foreach (var (k, vs) in r.Headers)
        {
            var name = k.ToLowerInvariant();
            foreach (var v in vs)
            {
                headers.Add(new(name, v ?? ""));
            }
        }
        var peer = ctx.Connection.RemoteIpAddress;
        if (peer != null && peer.AddressFamily == AddressFamily.InterNetworkV6 && peer.IsIPv4MappedToIPv6)
        {
            peer = peer.MapToIPv4();
        }
        var proto = r.Protocol;
        var hostHeader = r.Headers.Host.ToString();
        return new Req
        {
            Method = r.Method,
            Path = r.Path.HasValue ? r.Path.Value! : "/",
            RawPath = RawPathOf(ctx),
            Query = r.QueryString.HasValue ? r.QueryString.Value! : "",
            Host = hostHeader.Length > 0 ? hostHeader : r.Host.Host,
            HttpVersion = proto.StartsWith("HTTP/", StringComparison.Ordinal) ? proto[5..] : null,
            Peer = unix ? null : peer?.ToString(),
            PeerUnreadable = !unix && peer == null,
            Https = r.IsHttps,
            Headers = headers,
        };
    }

    /// <summary>The path as the client sent it: Request.Path is already decoded (all but %2F) and has
    /// PathBase cut off, so path rules match the raw target instead (contracts §D3 "Path matching") — the
    /// matcher canonicalises it. An origin-form target only; anything else (absolute-form, `*`) falls back
    /// to PathBase + Path.</summary>
    private static string RawPathOf(HttpContext ctx)
    {
        var target = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(target) && target[0] == '/')
        {
            var q = target.IndexOf('?');
            return q == -1 ? target : target[..q];
        }
        var r = ctx.Request;
        var p = (r.PathBase + r.Path).Value;
        return string.IsNullOrEmpty(p) ? "/" : p;
    }

    /// <summary>At most `limit` bytes (null when the declared or actual size exceeds it). The body is
    /// buffered and rewound so an app the request falls through to still sees all of it.</summary>
    public static async Task<byte[]?> ReadBody(HttpContext ctx, int limit)
    {
        var declared = ctx.Request.ContentLength ?? 0;
        if (declared > limit)
        {
            return null;
        }
        ctx.Request.EnableBuffering();
        var stream = ctx.Request.Body;
        var buf = new byte[limit + 1];
        var size = 0;
        while (size < buf.Length)
        {
            var n = await stream.ReadAsync(buf.AsMemory(size, buf.Length - size), ctx.RequestAborted).ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }
            size += n;
        }
        stream.Position = 0;
        return size > limit ? null : buf[..size];
    }

    /// <summary>The one place an Answer becomes an HTTP response (CamadaServeChallenge's IResult goes through it too).</summary>
    internal static async Task Write(HttpContext ctx, Answer a)
    {
        ctx.Response.StatusCode = a.Status;
        foreach (var (k, v) in a.Headers)
        {
            if (string.Equals(k, "content-security-policy", StringComparison.OrdinalIgnoreCase))
            {
                // the challenge page brings its own policy: one the app set earlier would block its solver, and
                // one set later from Response.OnStarting is undone by Run's callback (see PageCsp)
                PageCsp(ctx, v);
                ctx.Items[CspKey] = v;
                continue;
            }
            if (string.Equals(k, "cache-control", StringComparison.OrdinalIgnoreCase))
            {
                // a block or challenge answer is per-visitor: a public cache-control a middleware set earlier would
                // let a shared cache keep it (camada-all-8lp6)
                ctx.Response.Headers.CacheControl = v;
                continue;
            }
            ctx.Response.Headers.Append(k, v);
        }
        ctx.Response.ContentLength = a.Body.Length;
        if (a.Body.Length > 0)
        {
            await ctx.Response.Body.WriteAsync(a.Body, ctx.RequestAborted).ConfigureAwait(false);
        }
    }

    private const string CspKey = "camada.csp";

    private static void PageCsp(HttpContext ctx, string policy)
    {
        ctx.Response.Headers.Remove("Content-Security-Policy-Report-Only");
        ctx.Response.Headers.ContentSecurityPolicy = policy;
    }

    private async Task Run(HttpContext ctx, Passed p)
    {
        if (p.Ctx != null)
        {
            ctx.Items[ItemKey] = p.Ctx;
        }
        // Registered before the app runs, so the server (which fires OnStarting callbacks in reverse registration
        // order) runs it after every callback the app's middleware adds: a challenge page served by
        // CamadaServeChallenge() keeps its policy even when a header middleware sets CSP from OnStarting.
        ctx.Response.OnStarting(() =>
        {
            try
            {
                if (ctx.Items.TryGetValue(CspKey, out var csp) && csp is string policy)
                {
                    PageCsp(ctx, policy);
                }
                if (p.Rid != null && ctx.Response.StatusCode != StatusCodes.Status101SwitchingProtocols)   // never on a websocket handshake: the rid stays with the event
                {
                    ctx.Response.Headers["x-rid"] = p.Rid;
                }
                if (p.Ctx is { Signalled: true })   // read now: ServeChallenge() may have flagged it from inside the app
                {
                    foreach (var n in NoStoreHeaders)
                    {
                        ctx.Response.Headers[n] = "no-store";   // per client: replaces whatever the app set
                    }
                    ctx.Response.Headers["x-camada-challenge"] = "1";
                }
                if (p.SetCookie != null)
                {
                    ctx.Response.Headers.Append("Set-Cookie", p.SetCookie);
                }
            }
            catch (Exception err)
            {
                Guarded.LogRateLimited(err);
            }
            return Task.CompletedTask;
        });
        var fired = false;
        void Finish(int status)
        {
            if (fired || p.OnFinish == null)
            {
                return;
            }
            fired = true;
            try
            {
                if (p.Ctx != null)
                {
                    p.Ctx.Req.Route = (ctx.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText;
                }
            }
            catch (Exception err)
            {
                Guarded.LogRateLimited(err);
            }
            p.OnFinish(status);
        }
        try
        {
            await _next(ctx).ConfigureAwait(false);
        }
        catch
        {
            Finish(500);   // the app threw: the server will answer 500
            throw;
        }
        Finish(ctx.Response.StatusCode);
    }
}

// ASP.NET Core middleware: `app.UseCamada()` first in the pipeline, so camada answers before
// routing, static files or anything else runs. A Passed request runs the app with x-rid and the
// _sfp cookie stamped on the response as it starts (Response.OnStarting), the context in
// HttpContext.Items["camada"], and OnFinish(status) fired exactly once — with 500 when the app
// throws, the exception propagating unchanged.
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Camada.AspNetCore;

public sealed class CamadaMiddleware
{
    public const string ItemKey = "camada";

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
            req = ReqOf(ctx);
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

    public static Req ReqOf(HttpContext ctx)
    {
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
        var proto = r.Protocol ?? "";
        var hostHeader = r.Headers.Host.ToString();
        return new Req
        {
            Method = r.Method ?? "GET",
            Path = r.Path.HasValue ? r.Path.Value! : "/",
            Query = r.QueryString.HasValue ? r.QueryString.Value! : "",
            Host = hostHeader.Length > 0 ? hostHeader : r.Host.Host,
            HttpVersion = proto.StartsWith("HTTP/", StringComparison.Ordinal) ? proto[5..] : null,
            Peer = peer?.ToString(),
            Https = r.IsHttps,
            Headers = headers,
        };
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

    private static async Task Write(HttpContext ctx, Answer a)
    {
        ctx.Response.StatusCode = a.Status;
        foreach (var (k, v) in a.Headers)
        {
            ctx.Response.Headers.Append(k, v);
        }
        ctx.Response.ContentLength = a.Body.Length;
        if (a.Body.Length > 0)
        {
            await ctx.Response.Body.WriteAsync(a.Body, ctx.RequestAborted).ConfigureAwait(false);
        }
    }

    private async Task Run(HttpContext ctx, Passed p)
    {
        if (p.Ctx != null)
        {
            ctx.Items[ItemKey] = p.Ctx;
        }
        if (p.Rid != null || p.SetCookie != null)
        {
            ctx.Response.OnStarting(() =>
            {
                try
                {
                    if (p.Rid != null)
                    {
                        ctx.Response.Headers["x-rid"] = p.Rid;
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
        }
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

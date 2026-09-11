// The two-line install: `builder.Services.AddCamada(); app.UseCamada();` — then
// `ctx.CamadaScriptTag()` in HTML, `ctx.CamadaTrack("login_failed", user)` in handlers, and
// `ctx.CamadaServeChallenge()` for a route the app gates itself.
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Camada.AspNetCore;

public static class CamadaExtensions
{
    /// <summary>Registers one CamadaEngine built from the environment (and `configure`), routes the SDK's
    /// one-line-a-minute log through ILogger, and drains pending events on ApplicationStopping (0.5 s
    /// budget; no signal handlers of its own).</summary>
    public static IServiceCollection AddCamada(this IServiceCollection services, Action<CamadaOptions>? configure = null)
    {
        services.TryAddSingleton(sp =>
        {
            var logger = sp.GetService<ILoggerFactory>()?.CreateLogger("camada");
            if (logger != null)
            {
                Guarded.Sink = line => logger.LogError("{Line}", line);
            }
            var options = new CamadaOptions();
            configure?.Invoke(options);
            var engine = CamadaEngine.Create(options);
            sp.GetService<IHostApplicationLifetime>()?.ApplicationStopping.Register(() => engine.Queue?.Drain(0.5));
            return engine;
        });
        return services;
    }

    /// <summary>Put it first: camada answers blocks, challenges and the beacon endpoints before routing.</summary>
    public static IApplicationBuilder UseCamada(this IApplicationBuilder app) => app.UseMiddleware<CamadaMiddleware>();

    private static CamadaContext? ContextOf(HttpContext ctx) =>
        ctx.Items.TryGetValue(CamadaMiddleware.ItemKey, out var c) ? c as CamadaContext : null;

    private static CamadaEngine EngineFor(HttpContext ctx, CamadaContext? c) =>
        c?.Engine ?? ctx.RequestServices?.GetService<CamadaEngine>() ?? CamadaEngine.Default;

    /// <summary>The first-party beacon tag with this request's rid; "" without the middleware or with the beacon off.</summary>
    public static string CamadaScriptTag(this HttpContext ctx)
    {
        var c = ContextOf(ctx);
        return EngineFor(ctx, c).ScriptTag(c);
    }

    /// <summary>An app-context outcome event; the identifier is HMAC-hashed in-process. Never throws.</summary>
    public static void CamadaTrack(this HttpContext ctx, string ev, string? user = null)
    {
        var c = ContextOf(ctx);
        EngineFor(ctx, c).Track(c, ev, user);
    }

    /// <summary>The proof-of-work page (or 403 JSON) to return from a route you gate yourself; null once
    /// the browser holds a valid _cch, or when the client cannot be identified (fail open).</summary>
    public static IResult? CamadaServeChallenge(this HttpContext ctx)
    {
        var c = ContextOf(ctx);
        var a = EngineFor(ctx, c).ServeChallenge(c);
        return a == null ? null : new AnswerResult(a);
    }

    private sealed class AnswerResult : IResult
    {
        private readonly Answer _a;

        public AnswerResult(Answer a) => _a = a;

        public async Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = _a.Status;
            foreach (var (k, v) in _a.Headers)
            {
                httpContext.Response.Headers.Append(k, v);
            }
            httpContext.Response.ContentLength = _a.Body.Length;
            await httpContext.Response.Body.WriteAsync(_a.Body, httpContext.RequestAborted).ConfigureAwait(false);
        }
    }
}

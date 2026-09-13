# Camada

camada for .NET: enforces the tenant snapshot inline (your ordered custom rules, then allow,
block, challenge), serves a first-party proof-of-work challenge page and beacon, records the
outcomes your handlers know (`CamadaTrack()`), and ships wire events in batches off the request
path. One package (NuGet id `Camada`, namespace `Camada`) with an ASP.NET Core middleware and
three `HttpContext` helpers. Fails open by design: a camada outage or bug never 5xxes your app.

Not yet on NuGet — reference it from a sibling checkout:
`<ProjectReference Include="../camada-dotnet/src/Camada/Camada.csproj" />` (as
[`camada-dotnet-example`](../camada-dotnet-example) does); publishing is one decision with the npm
packages (SDK-G01). .NET 8, no runtime dependencies beyond the ASP.NET Core shared framework.

## Quickstart

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCamada();      // one engine from the environment, drained on shutdown

var app = builder.Build();
app.UseCamada();                   // FIRST: camada answers before routing, static files, anything
app.MapGet("/", (HttpContext ctx) => Results.Content($"<html><head>{ctx.CamadaScriptTag()}</head>…", "text/html"));
app.Run();
```

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

`AddCamada()` builds the engine when the container first resolves it — on the first request
through the middleware. That build starts the snapshot poll on a background task and never
blocks, so the request that triggered it is answered cold: it passes (fail open), and so does
anything else that arrives before that first poll lands (a few hundred milliseconds against a
local analyst; snapshot-size and network bound). To enforce from request 1, warm the engine at
startup by waiting for the boot poll — a bounded loop, so an unreachable analyst leaves it cold
and the app still starts and fails open:

```csharp
var engine = app.Services.GetRequiredService<CamadaEngine>();   // builds it; the boot poll is already running
if (engine.Snap != null)                                       // null when CAMADA_KEY is unset or CAMADA_DISABLED=1
{
    var deadline = Environment.TickCount64 + 5000;
    while (engine.Snap.Verdict(new MatchInput { Ip = "0.0.0.0" }).Reason == "cold" && Environment.TickCount64 < deadline)
    {
        Thread.Sleep(10);
    }
}
```

`engine.Snap.Refresh()` is not the warm-up: it waits behind the boot poll that is already in
flight and then polls once more, on the network, before your app can start; the loop above
returns the moment the boot poll lands.

Without `CAMADA_KEY` the engine is inert (one log line, no requests, no enforcement). An app
that reads its own config hands the values in through the options — credentials still travel as
an environment map, never as constructor arguments:

```csharp
builder.Services.AddCamada(o => o.Env = new Dictionary<string, string?> { ["CAMADA_KEY"] = myKey, ["CAMADA_INGEST_URL"] = myIngest });
```

Outside the generic host (a bare `IApplicationBuilder`), `UseCamada()` alone falls back to
`CamadaEngine.Default`, a lazy singleton wired from the process environment on first use;
`CamadaEngine.Configure(options)` replaces it, and its pending events drain on `ProcessExit`.

## What it does per request

1. Keeps the snapshot fresh. An ASP.NET Core server is a long-lived process, so the default is a
   background poll task on a `PeriodicTimer` at the cadence your tenant config sets
   (`poll_seconds`), with ETag/304 and gzip on the wire. `CAMADA_SERVERLESS=1` switches to a
   per-request staleness check with no timer. Every poll and event batch carries
   `x-camada-sdk: @camada/dotnet/<version>`, and polls ask for snapshot v5
   (`x-camada-snapshot: 5`) — the container that carries your ordered custom rules.
2. Resolves the client from the socket peer (`HttpContext.Connection.RemoteIpAddress`), combined
   with `X-Forwarded-For` only under your tenant's trusted-proxy config (or `CAMADA_TRUSTED_PROXY`
   locally). A forwarded header on its own is never the ip: any caller can set it. The SDK never
   reads the peer through ASP.NET Core's forwarded-headers middleware — if you add
   `UseForwardedHeaders()`, keep `UseCamada()` before it, so camada judges the raw header itself.
3. Enforces before anything else, beacon endpoints included: your ordered custom rules first (first
   match wins; they read ip, path, user-agent and request headers), then allow → block → challenge.
   A block answers `403 Forbidden` with `x-block-reason`, `x-block-version` and, when a rule
   decided, `x-block-rule`; its event ships with `blk` (and `rl`). A `warn` rule passes and stamps
   `wrn`; a `skip` rule passes with nothing stamped. Cold (no snapshot yet) passes: fail open.
4. Challenge: a `challenge` verdict gets the self-contained proof-of-work page (or 403 JSON for a
   non-HTML request); `POST /__camada/challenge` verifies the solution, sets `_cch` (bound to the
   ip, one hour) and 302s back. A request whose ip cannot be resolved is never challenged.
5. Serves the beacon: `GET /_cam/b.js` (the `@camada/browser` build, vendored as an embedded
   resource) and `POST /_cam/fp` (≤ 32 KB, relayed onto the event batch as a `sig: 1` row with the
   ip camada resolved). Both fall through to your app when the tenant switched the beacon off.
6. Runs your app with `x-rid` and the `_sfp` session cookie on its response (stamped from
   `Response.OnStarting`, so a handler that clears headers still carries them), the context in
   `HttpContext.Items["camada"]`, and when the response is done ships one redacted event: method,
   host, path, scrubbed query, status, latency, header names/sizes/order, the matched route
   pattern, the auth scheme (never the credential), cookie count (never values). An exception in
   your app ships as `st: 500` and propagates unchanged.

## Options

`AddCamada(o => …)` / `new CamadaEngine(options)`; everything credential-shaped comes from the
environment.

| option | default | meaning |
|---|---|---|
| `Env` | the process environment | where `CAMADA_*` are read from (the process one is read per request, for the kill switch) |
| `Transport` | `HttpClient` | the delegate that reaches the analyst (tests inject a fake) |
| `RefreshS` | server-steered | poll cadence in seconds; set, it is pinned |
| `Challenge` | `true` | serve the proof-of-work page for challenge verdicts (`CAMADA_CHALLENGE=0` too) |
| `ChallengePath` | `/__camada/challenge` | where the page posts its solution |
| `SnapshotVersion` | `5` | 4 drops your custom rules; 3 the allow/challenge sides too |
| `ScriptPath` / `FpPath` | `/_cam/b.js` / `/_cam/fp` | the beacon endpoints; keep them in one directory |

Env: `CAMADA_KEY` (or `CAMADA_TOKEN` + `CAMADA_SNAPSHOT_TOKEN`), `CAMADA_INGEST_URL`,
`CAMADA_SNAPSHOT_URL`, `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N | cidrs:a,b`),
`CAMADA_SERVERLESS=1`, `CAMADA_CHALLENGE=0`, and the kill switch `CAMADA_DISABLED=1` (checked per
request; set at boot, no timer starts at all).

## The first-party beacon

```csharp
app.MapGet("/", (HttpContext ctx) => Results.Content($"<html><head>{ctx.CamadaScriptTag()}</head>…", "text/html"));
```

The tag is `<script src="/_cam/b.js?r=<rid>" async>`, so the beacon joins the page view that
served it. Move both paths with `ScriptPath` / `FpPath` when `/_cam/` is not yours; the script
derives the post path from its own URL, so the two must share a directory.

## App-context events

```csharp
ctx.CamadaTrack("login_failed", user: email);
```

The identifier is HMAC-hashed in-process with your ingest token; the raw value never reaches the
queue. `CamadaTrack()` never throws; on a request the middleware did not run for it still ships
the event, with no rid, sid or ip to join it to. The event name is free-form; the analyst's
app-context rules read this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a login attempt settled; pass `user:` so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

A route you gate yourself: `ctx.CamadaServeChallenge()` returns the page as an `IResult` to
return from the handler until the browser holds a valid `_cch`, then `null`:

```csharp
app.MapGet("/challenge-me", (HttpContext ctx) => ctx.CamadaServeChallenge() ?? Results.Content(page, "text/html"));
```

## What this tap can see

`sdk-dotnet` is an in-app tap: status, latency, session, the beacon's browser signals and your
outcomes. The event carries the header order as `IHeaderDictionary` reports it (`hord`), which is
not the wire's order under Kestrel; the analyst knows what this tap can see and never scores the
absence of header order, ASN, country or a TLS fingerprint against a request; ASN and country it
resolves itself. Enforcement at this position covers ip, path, user-agent and header conditions —
ASN, country and TLS entries fail open in-app. `matches` patterns are JS regexes: they run on
`Regex` in ECMAScript mode (named groups, `[^]`, `\cX`, and `\d`/`\w`/`\b` ASCII as JS reads them);
a spelling that mode refuses is retried on the default engine, one neither accepts never matches
here while it does at the edge, and every match runs under a 50 ms timeout that reads as no match.
Two anchors read wider than in JS: `$` also matches before a final `\n`, and `.` also matches `\r`
(header values cannot carry either on the wire; a path rarely does).

## Deploying it

- Every process polls its own snapshot (about 5 MB resident) and flushes its own batches; the
  tenant's `poll_seconds` keeps the cadence honest across a fleet.
- Pending events drain on the host's `ApplicationStopping` within half a second, and every engine
  also drains on `ProcessExit` (what a bare `CamadaEngine.Default` relies on). No signal handlers
  are installed — an app owns its own shutdown — so a process killed outright may drop its last
  batch.
- Serverless: `CAMADA_SERVERLESS=1`. A cold invocation fails open and catches up on the next one.
- The poll is a plain background task, not an `IHostedService`: it needs no host to run under and
  starts with the engine. A hosted-service wrapper is deferred on purpose.
- NuGet packaging carries the basics (id, version, license, README); the rest of the metadata
  (icon, symbols, source link) is deferred until the family publishes.

## Fail open

Every entry point runs inside the fail-open envelope: a dead ingest drops telemetry (logged at
most once a minute, through `ILogger` under `AddCamada()` or stderr otherwise — the message only,
never a stack trace), a corrupt snapshot keeps the previous one, a bug in the package costs the
request its join, never its response. `CAMADA_DISABLED=1` bypasses everything.

## Development

```
dotnet format --verify-no-changes && dotnet build -warnaserror && dotnet test
```

The suite reads the golden snapshot fixtures from the `camada-core` sibling checkout (or
`CAMADA_FIXTURES_DIR`) and pins the vendored beacon to `camada-browser/dist/auto.global.js`
(`npm run build` there first, then `scripts/sync-beacon.sh` after a beacon release; or
`CAMADA_BROWSER_DIST`). Both fail by name when the checkout is missing rather than skipping.

The version lives in one place, the `<Version>` element of `src/Camada/Camada.csproj` (what the
sibling drift guards parse), repeated as `CamadaVersion.Value`; `VersionTests` holds the two
together.

[`camada-dotnet-example`](../camada-dotnet-example) is the hand-test bench (a minimal API on
:3007), and `node scripts/e2e-sdk-dotnet.mjs` in `camada/edge-analyst` drives it against a seeded
local analyst over real HTTP, cold first request included.

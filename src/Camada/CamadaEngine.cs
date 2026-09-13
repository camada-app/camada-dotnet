// The engine: the host-neutral request handling the middleware delegates to (the .NET twin of
// camada-python's Camada). An adapter turns its request into a Req, asks WantsBody() and reads
// at most that many bytes, then calls Handle(): an Answer means camada fully answered the
// request (block, challenge, verify, beacon endpoints); a Passed means run the app, stamp the
// rid header and session cookie on its response, and call OnFinish(status) once when it is
// done. Everything runs inside the fail-open envelope: a camada bug must never 5xx the customer,
// and CAMADA_DISABLED=1 bypasses the SDK entirely.
using System.Text;
using System.Text.Json;
using Camada.Challenge;
using Camada.Events;
using Camada.Snapshot;

namespace Camada;

public sealed class CamadaEngine
{
    // Tap identifier this SDK claims on the wire. The server validates against its own enum and
    // derives the capability mask itself (edge-analyst src/capabilities.js): an SDK can never grant
    // itself capability bits, only name its position — and an unknown name is silently read as a
    // proxy, so this literal is load-bearing.
    public const string Tap = "sdk-dotnet";
    public const string KillSwitchEnv = "CAMADA_DISABLED";
    public const string DefaultScriptPath = "/_cam/b.js";
    public const string DefaultFpPath = "/_cam/fp";
    public const int FpMax = 32 * 1024;                 // matches the server's /fp cap: never accept what ingest will 413
    public const string DefaultChallengePath = "/__camada/challenge";
    public const int BodyMax = 4 * 1024;                // the verify form is ~120 bytes; anything larger is not ours
    public const string SessionCookie = "_sfp";         // same cookie as the edge collector: sid/ns comparable across taps
    public const int SessionMaxAge = 2592000;           // 30 days

    private static readonly object DefaultLock = new();
    private static CamadaEngine? _default;

    private readonly Func<string, string?> _getEnv;
    public string ScriptPath { get; }
    public string FpPath { get; }
    public string ChallengePath { get; }
    public bool ChallengeOn { get; }
    public Env? Env { get; }
    public SnapshotClient? Snap { get; }
    public EventQueue? Queue { get; }
    public Kit? Kit { get; }

    /// <summary>Tests only: replaces the decision step so the fail-open envelope can be proven.</summary>
    internal Func<Req, byte[]?, Result>? DecideHook { get; set; }

    public CamadaEngine(CamadaOptions? options = null)
    {
        var o = options ?? new CamadaOptions();
        _getEnv = o.Env != null ? name => o.Env.GetValueOrDefault(name) : Environment.GetEnvironmentVariable;
        ScriptPath = o.ScriptPath;
        FpPath = o.FpPath;
        ChallengePath = o.ChallengePath;
        ChallengeOn = o.Challenge && _getEnv("CAMADA_CHALLENGE") != "0";
        Env = Camada.Env.Resolve(o.Env ?? Camada.Env.Process());
        if (Env == null || _getEnv(KillSwitchEnv) == "1")
        {
            return;   // unconfigured or killed at boot: no loop, no exit hooks, truly silent
        }
        Snap = new SnapshotClient(
            Env.SnapshotUrl, Env.SnapToken, refreshS: o.RefreshS, mode: Env.Serverless ? SnapshotMode.Lazy : SnapshotMode.Timer,
            transport: o.Transport, sdk: CamadaVersion.SdkId, snapshotVersion: o.SnapshotVersion);
        Queue = new EventQueue(Env.IngestUrl, Env.IngestToken, transport: o.Transport, sdk: CamadaVersion.SdkId);
        Kit = new Kit(Env.Secret);
        Snap.Start();
        Queue.InstallExitFlush();
    }

    /// <summary>Builds an engine and says so, once, when the environment leaves it inert.</summary>
    public static CamadaEngine Create(CamadaOptions? options = null)
    {
        var e = new CamadaEngine(options);
        if (e.Env == null)
        {
            Guarded.LogRateLimited("CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive");
        }
        return e;
    }

    /// <summary>The lazy singleton wired from the process environment on first use: what the middleware
    /// falls back to when no engine was registered with AddCamada().</summary>
    public static CamadaEngine Default
    {
        get
        {
            lock (DefaultLock)
            {
                return _default ??= Create();
            }
        }
    }

    /// <summary>Replaces the default engine (stopping the old one) — for explicit wiring outside DI.</summary>
    public static CamadaEngine Configure(CamadaOptions? options = null)
    {
        lock (DefaultLock)
        {
            _default?.Stop();
            _default = Create(options);
            return _default;
        }
    }

    internal static void ResetDefaultForTests(CamadaOptions? options)
    {
        lock (DefaultLock)
        {
            _default?.Stop();
            _default = options == null ? null : new CamadaEngine(options);
        }
    }

    public bool Disabled => Env == null || _getEnv(KillSwitchEnv) == "1";

    public long NowMs() => Builder.NowMs();

    private TrustedProxy? TrustedProxyConfig()
    {
        if (Env?.TrustedProxy != null)
        {
            return Env.TrustedProxy;   // explicit local override wins
        }
        return Snap?.Config?.TrustedProxy;
    }

    private bool BeaconEnabled() => Snap != null && Snap.Config?.Beacon != false;

    private string? IpOf(Req req) => Ip.ResolveClientIp(req.Peer, req.Header("x-forwarded-for"), TrustedProxyConfig());

    private static bool Secure(Req req) => req.Https || req.Header("x-forwarded-proto") == "https";

    private static string? SidOf(Req req) => CookieValue(req.Header("cookie"), SessionCookie);

    public static string? CookieValue(string? cookie, string name)
    {
        var src = "; " + (cookie ?? "");
        var i = src.IndexOf("; " + name + "=", StringComparison.Ordinal);
        if (i == -1)
        {
            return null;
        }
        var start = i + name.Length + 3;
        var j = src.IndexOf(';', start);
        return j == -1 ? src[start..] : src[start..j];
    }

    // ---- the adapter contract ----

    /// <summary>The byte cap to read the body under, when camada itself may answer this request.</summary>
    public int? WantsBody(string method, string path)
    {
        if (Disabled || method != "POST")
        {
            return null;
        }
        if (path == FpPath && BeaconEnabled())
        {
            return FpMax;
        }
        if (path == ChallengePath && ChallengeOn)
        {
            return BodyMax;
        }
        return null;
    }

    /// <summary>Never throws. `body` is the request body when WantsBody() asked for one, or null when
    /// the adapter refused to read it (declared or actual size over the cap).</summary>
    public Result Handle(Req req, byte[]? body = null)
    {
        try
        {
            return DecideHook != null ? DecideHook(req, body) : Decide(req, body);
        }
        catch (Exception err)   // a camada bug costs the join, never the request
        {
            Guarded.LogRateLimited(err);
            return Passed.Inert;
        }
    }

    private Result Decide(Req req, byte[]? body)
    {
        if (Disabled || Snap == null || Queue == null || Env == null)
        {
            return Passed.Inert;
        }
        var queue = Queue;
        var t0 = Environment.TickCount64;
        Snap.EnsureFresh();
        var ip = IpOf(req);

        // Enforce before anything else, beacon endpoints included — fail open while cold. The
        // custom rules read the user agent and the request headers (§D3).
        var v = Snap.Verdict(new MatchInput { Ip = ip, Path = req.Path, Ua = req.Header("user-agent"), Header = req.Header });
        if (v.Block)
        {
            var headers = new List<KeyValuePair<string, string>>
            {
                new("content-type", "text/plain"), new("x-block-reason", v.Reason ?? ""), new("x-block-version", v.Version ?? ""),
            };
            if (v.Rule != null)
            {
                headers.Add(new("x-block-rule", v.Rule));   // a custom rule blocked: name it, so the customer knows which row to edit
            }
            var ev = Event(req, Guid.NewGuid().ToString(), null, false, ip);
            ev["st"] = 403;   // blocked requests always ship: silent expiry makes blocks oscillate
            ev["blk"] = v.Reason;   // the reason rides the event so the analyst counts SDK blocks, not the app's own 403s
            if (v.Rule != null)
            {
                ev["rl"] = v.Rule;
            }
            queue.Push(ev);
            return new Answer(403, headers, "Forbidden"u8.ToArray());
        }
        // `warn` passes the request and only marks its event (below, on finish); a skip passes
        // with nothing stamped at all — it is the absence of enforcement.

        // A challenge needs a resolved client IP: the nonce and the _cch cookie are bound to it,
        // so without one a single solve would mint a cookie every unidentified client could
        // present. No ip -> no challenge (fail open), the same stance ip rules take.
        if (ChallengeOn && !string.IsNullOrEmpty(ip))
        {
            // The verify endpoint answers first: a challenged client must be able to reach it.
            if (req.Method == "POST" && req.Path == ChallengePath)
            {
                return VerifyChallenge(req, body, ip);
            }
            if (v.Challenge && !ChallengePassed(req, ip))
            {
                return ServeChallengeAnswer(req, ip, SidOf(req));
            }
        }

        if (BeaconEnabled())
        {
            if (req.Method == "GET" && req.Path == ScriptPath)
            {
                var jsHeaders = new List<KeyValuePair<string, string>> { new("content-type", "application/javascript"), new("cache-control", "public, max-age=3600") };
                return new Answer(200, jsHeaders, BeaconJs.Bytes);
            }
            if (req.Method == "POST" && req.Path == FpPath)
            {
                return RelayBeacon(body, ip);
            }
        }

        var rid = Guid.NewGuid().ToString();
        var sid = SidOf(req);
        var newSession = string.IsNullOrEmpty(sid);
        string? setCookie = null;
        if (newSession)
        {
            sid = Guid.NewGuid().ToString();
            setCookie = $"{SessionCookie}={sid}; Path=/; Max-Age={SessionMaxAge}; HttpOnly; SameSite=Lax";
            if (Secure(req))
            {
                setCookie += "; Secure";
            }
        }
        var ctx = new CamadaContext(rid, sid!, ip, req, this);

        var cfg = Snap.Config;
        var excluded = cfg != null && cfg.Exclude.Any(x => req.Path.StartsWith(x, StringComparison.Ordinal));
        var sample = cfg?.Sample;
        var sampled = Random.Shared.NextDouble() < (sample ?? 1.0);   // sampling, not crypto
        var warnRule = v.Warn ? v.Rule : null;

        void OnFinish(int status)
        {
            try
            {
                // ServeChallenge() may have answered from inside the app, and it already shipped
                // the `blk: "challenge"` row — one request, one event.
                if (ctx.Challenged || excluded || !sampled)
                {
                    return;
                }
                var ev = Event(req, rid, sid, newSession, ip);
                ev["st"] = status;
                ev["dur"] = (int)(Environment.TickCount64 - t0);
                if (!string.IsNullOrEmpty(req.Route))
                {
                    ev["rt"] = req.Route;
                }
                if (warnRule != null)
                {
                    ev["wrn"] = warnRule;   // §D3: the warn rule that let this request through
                }
                queue.Push(ev);
            }
            catch (Exception err)
            {
                Guarded.LogRateLimited(err);
            }
        }

        return new Passed(rid, setCookie, ctx, OnFinish);
    }

    private static Dictionary<string, object?> Event(Req req, string rid, string? sid, bool newSession, string? ip)
    {
        var info = new RequestInfo(req.Method, req.Host, req.Path, req.Query, req.Headers, ip, req.HttpVersion);
        return Builder.BuildWireEvent(info, tap: Tap, rid: rid, sid: sid, newSession: newSession);
    }

    // ---- beacon ----

    /// <summary>Answers 204, and queues the beacon as a `sig: 1` row with the trusted-proxy-resolved
    /// client IP: it rides the next event batch. Junk bodies are dropped, never shipped.</summary>
    private Answer RelayBeacon(byte[]? body, string? ip)
    {
        if (body == null)
        {
            return new Answer(413, Array.Empty<KeyValuePair<string, string>>(), Array.Empty<byte>());
        }
        var answer = new Answer(204, new List<KeyValuePair<string, string>> { new("cache-control", "no-store") }, Array.Empty<byte>());
        Dictionary<string, object?>? row;   // values land as JsonElement: a non-object body throws, `null` is null
        try
        {
            row = JsonSerializer.Deserialize<Dictionary<string, object?>>(body);
        }
        catch (JsonException)
        {
            return answer;
        }
        if (row == null)
        {
            return answer;
        }
        row["sig"] = 1;   // spread first: ip and tap are the server's word
        row["ip"] = ip;
        row["tap"] = Tap;
        Queue!.Push(row);
        return answer;
    }

    /// <summary>For HTML templates: the first-party beacon tag with the request's rid.</summary>
    public string ScriptTag(CamadaContext? ctx)
    {
        if (Disabled || !BeaconEnabled())
        {
            return "";
        }
        var rid = ctx?.Rid;
        return $"<script src=\"{ScriptPath}{(string.IsNullOrEmpty(rid) ? "" : "?r=" + rid)}\" async></script>";
    }

    // ---- challenge ----

    private bool ChallengePassed(Req req, string? ip) =>
        Kit != null && Kit.TokenValid(ip, NowMs(), CookieValue(req.Header("cookie"), Format.ChallengeCookie));

    private Answer PageAnswer(string ip, string to)
    {
        var html = Page.ChallengePage(nonce: Kit!.Nonce(ip, NowMs()), action: ChallengePath, to: to);
        var headers = new List<KeyValuePair<string, string>>
        {
            new("content-type", "text/html; charset=utf-8"), new("cache-control", "no-store"), new("x-camada-challenge", "1"),
        };
        return new Answer(403, headers, Encoding.UTF8.GetBytes(html));
    }

    /// <summary>403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
    /// `blk: "challenge"` event — a served challenge is reported like a block (contract §D2).</summary>
    private Answer ServeChallengeAnswer(Req req, string ip, string? sid)
    {
        var to = Format.SafeReturnTo(req.Path + req.Query);
        Answer answer;
        if (Format.WantsHtml(req.Header("accept"), req.Header("sec-fetch-dest")))
        {
            answer = PageAnswer(ip, to);
        }
        else
        {
            var headers = new List<KeyValuePair<string, string>>
            {
                new("content-type", "application/json"), new("cache-control", "no-store"), new("x-camada-challenge", "1"),
            };
            answer = new Answer(403, headers, "{\"error\":\"challenge_required\"}"u8.ToArray());
        }
        try
        {
            var ev = Event(req, Guid.NewGuid().ToString(), sid, false, ip);
            ev["st"] = 403;
            ev["blk"] = "challenge";
            Queue!.Push(ev);
        }
        catch (Exception err)   // the response is decided; telemetry must never undo that
        {
            Guarded.LogRateLimited(err);
        }
        return answer;
    }

    /// <summary>POST from the challenge page: validate the nonce and the proof of work, set _cch, 302
    /// back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`.</summary>
    private Answer VerifyChallenge(Req req, byte[]? body, string ip)
    {
        if (body == null)
        {
            return new Answer(413, Array.Empty<KeyValuePair<string, string>>(), Array.Empty<byte>());
        }
        var form = Format.ParseFormBody(Encoding.UTF8.GetString(body));
        var to = Format.SafeReturnTo(form.GetValueOrDefault("to"));
        var now = NowMs();
        if (!Kit!.Verify(ip, now, form.GetValueOrDefault("nonce"), form.GetValueOrDefault("solution")))
        {
            return PageAnswer(ip, to);
        }
        var cookie = Format.Cookie(Kit.Issue(ip, now), Secure(req));
        var headers = new List<KeyValuePair<string, string>> { new("location", to), new("set-cookie", cookie), new("cache-control", "no-store") };
        var ev = Event(req, Guid.NewGuid().ToString(), SidOf(req), false, ip);
        ev["st"] = 200;
        ev["ch"] = 1;   // challenge passed (contract §A3 ingest field)
        Queue!.Push(ev);
        return new Answer(302, headers, Array.Empty<byte>());
    }

    /// <summary>Serve the challenge for this request on demand — for a route the app wants to gate
    /// itself. Null when the client already holds a valid _cch (render your own page), or when
    /// the client cannot be identified (fail open).</summary>
    public Answer? ServeChallenge(CamadaContext? ctx)
    {
        try
        {
            if (Disabled || Kit == null || ctx == null)
            {
                return null;
            }
            var ip = ctx.Ip;
            if (string.IsNullOrEmpty(ip) || ChallengePassed(ctx.Req, ip))
            {
                return null;
            }
            ctx.Challenged = true;
            return ServeChallengeAnswer(ctx.Req, ip, ctx.Sid);
        }
        catch (Exception err)
        {
            Guarded.LogRateLimited(err);
            return null;
        }
    }

    // ---- app-context events ----

    /// <summary>App-context outcome events (login failed, signup, ...). The identifier is HMAC-hashed
    /// in-process; the raw value never reaches the queue.</summary>
    public void Track(CamadaContext? ctx, string ev, string? user = null)
    {
        try
        {
            if (Disabled || Queue == null || Env == null)
            {
                return;
            }
            var uid = string.IsNullOrEmpty(user) ? null : Redact.HashUserId(user, Env.IngestToken);
            var row = new Dictionary<string, object?>
            {
                ["tap"] = Tap,
                ["et"] = ev,
                ["uid"] = uid,
                ["rid"] = ctx?.Rid,
                ["sid"] = ctx?.Sid,
                ["ip"] = ctx?.Ip,
                ["ts"] = NowMs(),
            };
            Queue.Push(row);
        }
        catch (Exception err)
        {
            Guarded.LogRateLimited(err);
        }
    }

    public void Stop()
    {
        Snap?.Stop();
        Queue?.Stop();
    }
}

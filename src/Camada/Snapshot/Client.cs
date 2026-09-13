// SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the
// GET /snapshot contract (ported from @camada/core src/snapshot/client.ts):
//   200  [u32 LE meta-length][meta JSON][BLK container] + etag + x-camada-config
//   304  nothing changed; config header repeated (config refreshes every poll for free)
//   204  authenticated, no snapshot published -> enforce nothing, fail open
// Semantics ported exactly: single-in-flight load; loaded_at stamped even on 204 (retry per
// poll cadence, not per request); any error keeps the previous snapshot; cold = fail open.
// Timers are Tasks here: timer mode runs one PeriodicTimer loop per client; lazy mode kicks a
// Task from EnsureFresh() so the request path never waits on the network.
using System.Buffers.Binary;
using System.Text.Json;

namespace Camada.Snapshot;

public enum SnapshotMode
{
    Timer,
    Lazy,
}

public sealed class SnapshotClient
{
    public const double DefaultRefreshS = 30.0;
    // 5 carries the tenant's ordered custom rules (§D3); a tenant without one is answered with the next container down.
    public const int DefaultSnapshotVersion = 5;

    public static readonly MatchResult Cold = new(Reason: "cold");   // never loaded yet: fail open, mirrors the collector
    public static readonly MatchResult None = new();

    public string Url { get; }
    public string Token { get; }
    public double TimeoutS { get; }
    public SnapshotMode Mode { get; }
    public string? Sdk { get; }                        // '<package>/<version>': sent as x-camada-sdk on every poll (SDK-03)
    public int SnapshotVersion { get; }                // 5 asks for the custom rules too; 4 the sides only; 3 opts out of both
    public Transport Transport { get; set; }
    public double RefreshS { get; private set; }       // leave unset and the server's poll_seconds steers it; set it and it is pinned
    public RemoteConfig? Config { get; private set; }

    private volatile Matcher? _matcher;
    private readonly bool _pinned;
    private string? _etag;
    private long _loadedAt;                            // Environment.TickCount64 of the last accepted answer (0: none yet)
    private volatile bool _loaded;                     // an answer has been applied: the matcher (or its absence) is final
    private readonly SemaphoreSlim _loading = new(1, 1);
    private readonly object _timerLock = new();
    private CancellationTokenSource? _stop;
    private PeriodicTimer? _timer;

    public SnapshotClient(
        string url,
        string token,
        double? refreshS = null,
        double timeoutS = 3.0,
        SnapshotMode mode = SnapshotMode.Timer,
        Transport? transport = null,
        string? sdk = null,
        int snapshotVersion = DefaultSnapshotVersion)
    {
        Url = url;
        Token = token;
        TimeoutS = timeoutS;
        Mode = mode;
        Sdk = sdk;
        SnapshotVersion = snapshotVersion;
        Transport = transport ?? HttpClientTransport.Send;
        RefreshS = refreshS ?? DefaultRefreshS;
        _pinned = refreshS != null;
    }

    public Matcher? Matcher => _matcher;

    public void Start()
    {
        EnsureFresh();
        if (Mode != SnapshotMode.Timer)
        {
            return;
        }
        lock (_timerLock)
        {
            if (_stop != null)
            {
                return;
            }
            var cts = new CancellationTokenSource();
            var timer = new PeriodicTimer(TimeSpan.FromSeconds(RefreshS));
            _stop = cts;
            _timer = timer;
            _ = Task.Run(() => RunAsync(timer, cts.Token));
        }
    }

    private async Task RunAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                var period = TimeSpan.FromSeconds(RefreshS);
                if (timer.Period != period)
                {
                    timer.Period = period;   // the server may have steered the cadence since the last tick
                }
                EnsureFresh();
            }
        }
        catch (OperationCanceledException)
        {
            // stopped
        }
        catch (Exception err)
        {
            Guarded.LogRateLimited(err);
        }
    }

    public void Stop()
    {
        lock (_timerLock)
        {
            _stop?.Cancel();
            _stop?.Dispose();
            _timer?.Dispose();
            _stop = null;
            _timer = null;
        }
    }

    // 0.9 x refresh so a timer tick arriving at ~refresh-ε still refreshes; a full-interval
    // comparison makes every other tick a no-op (effective cadence 2x). Staleness follows the
    // stamp, not the cold flag: an answer whose frame the parser rejected is still an answer, and
    // is retried at the poll cadence — never once per request.
    public bool Stale
    {
        get
        {
            var at = Interlocked.Read(ref _loadedAt);
            return at == 0 || Environment.TickCount64 - at > RefreshS * 900;
        }
    }

    /// <summary>Kicks a refresh when stale; never blocks the request path, never throws. The single-in-flight
    /// slot is taken here, synchronously, so two callers racing cannot both start a load.</summary>
    public void EnsureFresh()
    {
        if (!Stale || !_loading.Wait(0))
        {
            return;
        }
        _ = Task.Run(LoadGuarded);
    }

    /// <summary>One synchronous poll: what tests and warm-ups call directly. It waits behind a poll already in
    /// flight (the boot poll, a timer tick) rather than skipping, so when it returns a poll has just completed.</summary>
    public void Refresh()
    {
        _loading.Wait();
        LoadGuarded();
    }

    /// <summary>Runs one Load() holding the single-in-flight slot the caller took, and releases it.</summary>
    private void LoadGuarded()
    {
        try
        {
            Load();
        }
        catch (Exception err)   // a poll that can never succeed must not be silent, nor fatal
        {
            Guarded.LogRateLimited(err);
        }
        finally
        {
            _loading.Release();
        }
    }

    private void Load()
    {
        var headers = new Dictionary<string, string> { ["authorization"] = $"Bearer {Token}", ["accept-encoding"] = "gzip" };
        if (_etag != null)
        {
            headers["if-none-match"] = _etag;
        }
        if (Sdk != null)
        {
            headers["x-camada-sdk"] = Sdk;
        }
        if (SnapshotVersion > 3)
        {
            headers["x-camada-snapshot"] = SnapshotVersion.ToString(System.Globalization.CultureInfo.InvariantCulture);   // a tenant without that container is answered with the next one down
        }
        var res = Transport(new TransportRequest("GET", Url, headers, null, TimeoutS));
        if (res.Status is not (200 or 204 or 304))
        {
            return;   // 401/5xx/network: keep what we have
        }
        Interlocked.Exchange(ref _loadedAt, Math.Max(1, Environment.TickCount64));   // 0 is reserved for "never answered"
        ReadConfig(res.Headers.GetValueOrDefault("x-camada-config"));
        if (res.Status == 304)
        {
            _loaded = true;
            return;
        }
        if (res.Status == 204)   // no snapshot published: enforce nothing
        {
            _matcher = null;
            _etag = null;
            _loaded = true;
            return;
        }
        var body = res.Body;
        if (body.Length < 4)
        {
            throw new SnapshotFormatException("camada: truncated snapshot frame");
        }
        var metaLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(body);
        if (metaLen < 0 || 4 + (long)metaLen > body.Length)
        {
            throw new SnapshotFormatException("camada: truncated snapshot frame");
        }
        using var meta = JsonDocument.Parse(new ReadOnlyMemory<byte>(body, 4, metaLen));
        var root = meta.RootElement;
        var version = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        // The server ships the v3, v4 and v5 bodies of one publish under the SAME meta.version and
        // different etags, so version alone cannot say "nothing changed".
        var etag = res.Headers.GetValueOrDefault("etag");
        var current = _matcher;
        if (current != null && version == current.Snap.Version && etag != null && etag == _etag)
        {
            return;
        }
        // ParseSnapshot throws on corrupt data -> caught by LoadGuarded, previous kept
        _matcher = new Matcher(Parser.ParseSnapshot(new ReadOnlyMemory<byte>(body, 4 + metaLen, body.Length - 4 - metaLen), root));
        _etag = etag;
        // not cold only once the matcher is in place: a reader that sees "loaded" must see the snapshot too
        _loaded = true;
    }

    private void ReadConfig(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return;
        }
        var cfg = RemoteConfig.Parse(raw);
        if (cfg == null)
        {
            return;   // keep the previous config
        }
        Config = cfg;
        // the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
        var secs = cfg.PollSeconds;
        if (secs is not { } s || _pinned || !double.IsFinite(s) || s < 5 || s == RefreshS)   // JSON admits 1e999
        {
            return;
        }
        RefreshS = s;
    }

    /// <summary>Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector.</summary>
    public MatchResult Verdict(MatchInput i)
    {
        if (!_loaded)
        {
            return Cold;
        }
        var m = _matcher;
        return m != null ? m.Match(i) : None;
    }
}

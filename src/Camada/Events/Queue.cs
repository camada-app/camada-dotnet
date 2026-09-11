// EventQueue: fire-and-forget batched shipping to POST /e (ported from @camada/core
// src/events/queue.ts). The collector ships one event per request; an in-process SDK batches,
// flushes on size or interval, and drains at exit — but the same law holds: NOTHING here may
// ever throw into the customer's request path, and a dead ingest must cost nothing but dropped
// telemetry. Defaults (15 s / 500): every flush is one request and one R2 put at the analyst,
// so the bill scales with instance count x flush cadence — not with traffic.
using System.Text.Json;

namespace Camada.Events;

public sealed class EventQueue
{
    private static readonly JsonSerializerOptions Wire = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

    public string Url { get; }                 // ingest base, e.g. https://analyst.example.com
    public string Token { get; }               // ingest token (x-tenant header)
    public int MaxBatch { get; }               // flush when the queue reaches this many (server caps at 1000)
    public int MaxQueue { get; }               // drop-oldest beyond this
    public double FlushS { get; }
    public double TimeoutS { get; }
    public string? Sdk { get; }                // '<package>/<version>': sent as x-camada-sdk on every batch (SDK-03)
    public Transport Transport { get; set; }
    public int Dropped => _dropped;            // debug counter, not an API promise

    private int _dropped;
    private readonly Queue<object> _q = new();
    private readonly object _lock = new();
    private readonly SemaphoreSlim _inflight = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, 1);
    private CancellationTokenSource? _stop;
    private bool _stopped;
    private bool _exitInstalled;

    public EventQueue(
        string url,
        string token,
        int maxBatch = 500,
        int maxQueue = 2000,
        double flushS = 15.0,
        double timeoutS = 2.0,
        Transport? transport = null,
        string? sdk = null)
    {
        Url = url.TrimEnd('/');
        Token = token;
        MaxBatch = maxBatch;
        MaxQueue = maxQueue;
        FlushS = flushS;
        TimeoutS = timeoutS;
        Sdk = sdk;
        Transport = transport ?? HttpClientTransport.Send;
    }

    public int Size
    {
        get
        {
            lock (_lock)
            {
                return _q.Count;
            }
        }
    }

    internal bool InFlight => _inflight.CurrentCount == 0;

    /// <summary>Synchronous, never throws. Starts the flush loop lazily on first push; a stopped queue
    /// stays stopped (Configure() replaces the engine rather than reviving one).</summary>
    public void Push(object ev)
    {
        try
        {
            int n;
            lock (_lock)
            {
                if (_q.Count >= MaxQueue)
                {
                    _q.Dequeue();
                    _dropped++;
                }
                _q.Enqueue(ev);
                n = _q.Count;
                if (_stop == null && !_stopped)
                {
                    var cts = new CancellationTokenSource();
                    _stop = cts;
                    _ = Task.Run(() => RunAsync(cts.Token));
                }
            }
            if (n >= MaxBatch)
            {
                Wake();
            }
        }
        catch (Exception err)   // never into the request path
        {
            Guarded.LogRateLimited(err);
        }
    }

    private void Wake()
    {
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
            // already signalled
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await _wake.WaitAsync(TimeSpan.FromSeconds(FlushS), ct).ConfigureAwait(false);
                if (ct.IsCancellationRequested)
                {
                    return;
                }
                Flush();
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

    /// <summary>Drains the queue, &lt;=1000 events per POST (the server slices there); single-in-flight;
    /// never throws. `wait` queues behind a flush already in flight instead of yielding to it —
    /// the exit drain needs the full queue gone, not just the batch someone else is posting.</summary>
    public void Flush(bool wait = false)
    {
        if (!(wait ? _inflight.Wait(Timeout.Infinite) : _inflight.Wait(0)))
        {
            return;
        }
        try
        {
            var headers = new Dictionary<string, string> { ["x-tenant"] = Token, ["content-type"] = "application/json" };
            if (Sdk != null)
            {
                headers["x-camada-sdk"] = Sdk;
            }
            while (true)
            {
                List<object> batch;
                lock (_lock)
                {
                    if (_q.Count == 0)
                    {
                        return;
                    }
                    var n = Math.Min(1000, _q.Count);
                    batch = new List<object>(n);
                    for (var i = 0; i < n; i++)
                    {
                        batch.Add(_q.Dequeue());
                    }
                }
                try
                {
                    var body = JsonSerializer.SerializeToUtf8Bytes(batch, Wire);
                    var res = Transport(new TransportRequest("POST", $"{Url}/e", headers, body, TimeoutS));
                    if (res.Status == 0)
                    {
                        throw new IOException("ingest unreachable");
                    }
                }
                catch (Exception err)
                {
                    Interlocked.Add(ref _dropped, batch.Count);
                    // Dropping telemetry is by design, doing it silently is not: a mount that can never
                    // reach ingest looks identical to a healthy one otherwise.
                    Guarded.LogRateLimited(err);
                }
            }
        }
        finally
        {
            _inflight.Release();
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            _stopped = true;
            _stop?.Cancel();
            _stop?.Dispose();
            _stop = null;
        }
        Wake();
    }

    /// <summary>Opt-in: drain at process exit within a small budget. No signal handlers — an app owns
    /// its own shutdown (AddCamada() hooks the host's ApplicationStopping instead); a process killed
    /// outright skips ProcessExit, which the README says out loud.</summary>
    public void InstallExitFlush(double budgetS = 0.5)
    {
        lock (_lock)
        {
            if (_exitInstalled)
            {
                return;
            }
            _exitInstalled = true;
        }
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Drain(budgetS);
    }

    /// <summary>A full drain (behind any flush in flight) on a pool thread, abandoned once the budget is spent.</summary>
    public void Drain(double budgetS = 0.5)
    {
        try
        {
            Task.Run(() => Flush(wait: true)).Wait(TimeSpan.FromSeconds(budgetS));
        }
        catch (Exception err)
        {
            Guarded.LogRateLimited(err);
        }
    }
}

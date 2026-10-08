// Snapshot poll pacing (camada-all-pbv9, contract v2), driven by camada-core's test/fixtures/poll/backoff.json:
// NextPollDelay's table, then client timelines on an injected tick clock.
using System.Text.Json;
using Camada.Snapshot;

namespace Camada.Tests;

public class BackoffTests
{
    private static readonly JsonElement Fx = Fixtures.ReadJson("poll/backoff.json");

    private static string? Str(JsonElement e, string k) =>
        e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    [Fact]
    public void DelayTable()
    {
        foreach (var c in Fx.GetProperty("delay").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString();
            var got = SnapshotClient.NextPollDelay(c.GetProperty("status").GetInt32(), Str(c, "retryAfter"), c.GetProperty("refreshSeconds").GetDouble());
            var want = c.GetProperty("expectDelaySeconds");
            if (want.ValueKind == JsonValueKind.Null)
            {
                Assert.True(got is null, name);
            }
            else
            {
                Assert.True(got is not null, name);
                Assert.True(Math.Abs(want.GetDouble() - got!.Value) < 1e-9, $"{name}: {got}");
            }
        }
    }

    [Fact]
    public void Timelines()
    {
        var blocked = new MatchInput { Ip = Fx.GetProperty("blockedIp").GetString() };
        foreach (var tl in Fx.GetProperty("timelines").EnumerateArray())
        {
            var a = new FakeAnalyst();
            long now = 0;
            var respond = a.Transport;
            var c = new SnapshotClient("https://analyst.test/snapshot", "snap-test", refreshS: tl.GetProperty("refreshSeconds").GetDouble(),
                mode: SnapshotMode.Lazy, transport: req => respond(req), sdk: "@camada/dotnet/0.0.0");
            c.Ticks = () => Interlocked.Read(ref now);
            var baseS = tl.GetProperty("clockBase").GetDouble();
            foreach (var st in tl.GetProperty("steps").EnumerateArray())
            {
                var where = $"{tl.GetProperty("name").GetString()} @t={st.GetProperty("t").GetDouble()}";
                now = (long)Math.Round((baseS + st.GetProperty("t").GetDouble()) * 1000);
                var poll = st.GetProperty("poll").GetBoolean();
                Assert.True(poll == c.Due, where);
                if (!poll)
                {
                    continue;
                }
                var r = st.GetProperty("respond");
                var status = r.GetProperty("status").GetInt32();
                var ra = Str(r, "retryAfter");
                respond = status == 200
                    ? a.Transport
                    : _ => new TransportResponse(status, ra is null ? new() : new() { ["retry-after"] = ra }, Array.Empty<byte>());
                c.Refresh();
                var after = st.GetProperty("after");
                var v = c.Verdict(blocked);
                Assert.True(after.GetProperty("cold").GetBoolean() == (v.Reason == "cold"), where + " cold");
                Assert.True(after.GetProperty("blocked").GetBoolean() == v.Block, where + " blocked");
            }
        }
    }

    private static SnapshotClient Gated(out Func<int> requests, out Action<long> advance, out Action<bool> fail, Func<TransportRequest, TransportResponse>? inner = null)
    {
        var a = new FakeAnalyst();
        var n = 0;
        var failing = false;
        long now = 1_000_000;
        var c = new SnapshotClient("https://analyst.test/snapshot", "snap-test", refreshS: 30, mode: SnapshotMode.Lazy,
            transport: req =>
            {
                if (inner != null)
                {
                    return inner(req);
                }
                if (!Volatile.Read(ref failing))
                {
                    return a.Transport(req);
                }
                Interlocked.Increment(ref n);
                return new TransportResponse(503, new() { ["retry-after"] = "30" }, Array.Empty<byte>());
            });
        c.Ticks = () => Interlocked.Read(ref now);
        requests = () => Volatile.Read(ref n);
        advance = ms => Interlocked.Add(ref now, ms);
        fail = f => Volatile.Write(ref failing, f);
        return c;
    }

    /// <summary>Request path under a closed gate: warm, stale, 503 retry-after 30 -> one request per 30 s.</summary>
    [Fact]
    public void RequestPathHonoursTheGate()
    {
        var c = Gated(out var requests, out var advance, out var fail);
        c.Refresh();                                    // warm with a 200
        advance(28_000);                                // stale, gate open
        fail(true);
        c.EnsureFresh();
        Assert.True(SpinWait.SpinUntil(() => !c.Due, 5000));
        Thread.Sleep(50);                               // the slot is released after the gate is written
        Assert.Equal(1, requests());
        for (var i = 0; i < 20; i++)
        {
            c.EnsureFresh();
        }
        Thread.Sleep(200);
        Assert.Equal(1, requests());                    // stale but not due
        advance(30_000);
        c.EnsureFresh();
        Assert.True(SpinWait.SpinUntil(() => requests() >= 2, 5000));
        Thread.Sleep(200);
        Assert.Equal(2, requests());                    // gate elapsed: one more poll
    }

    /// <summary>A transport that throws is a poll nobody answered: gated as status 0 and still logged.</summary>
    [Fact]
    public void ThrowingTransportIsLoggedAndGated()
    {
        var lines = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var old = Guarded.Sink;
        try
        {
            Guarded.Sink = lines.Enqueue;
            Guarded.ResetForTests();
            var c = Gated(out _, out var advance, out _, _ => throw new InvalidOperationException("boom"));
            c.Refresh();
            Assert.Contains(lines, l => l.Contains("boom"));
            Assert.False(c.Due);                        // gated as status 0
            advance(5_000);
            Assert.True(c.Due);                         // the 5 s floor elapsed
        }
        finally
        {
            Guarded.Sink = old;
        }
    }
}

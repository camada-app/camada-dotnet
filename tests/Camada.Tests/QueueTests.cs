// EventQueue: fire-and-forget batched shipping to POST /e. Nothing here may ever throw into the
// customer's request path, and a dead ingest must cost nothing but dropped telemetry.
using Camada.Events;

namespace Camada.Tests;

public class QueueTests
{
    private static EventQueue Queue(FakeAnalyst a, int maxBatch = 500, int maxQueue = 2000, double flushS = 15.0) =>
        new("https://analyst.test", "tok-test", maxBatch: maxBatch, maxQueue: maxQueue, flushS: flushS, transport: a.Transport, sdk: "@camada/dotnet/0.0.0");

    private static Dictionary<string, object?> Row(string k, object v) => new() { [k] = v };

    private static string Flat(FakeAnalyst a) => string.Join("|", a.Events.Select(b => string.Join(",", b.Select(e => e.Values.First().GetRawText()))));

    [Fact]
    public void FlushPostsAJsonArrayWithTheTenantAndSdkHeaders()
    {
        var a = new FakeAnalyst();
        var q = Queue(a);
        q.Push(Row("p", "/"));
        q.Flush();
        Assert.Equal("\"/\"", Flat(a));
        Assert.Equal(new[] { "@camada/dotnet/0.0.0" }, a.SdkHeaders);
        q.Stop();
    }

    [Fact]
    public void FlushesWhenTheBatchSizeIsReached()
    {
        var a = new FakeAnalyst();
        var q = Queue(a, maxBatch: 3, flushS: 60);
        for (var i = 0; i < 3; i++)
        {
            q.Push(Row("i", i));
        }
        Hosts.WaitUntil(() => a.Events.Count > 0);
        Assert.Equal("0,1,2", Flat(a));
        q.Stop();
    }

    [Fact]
    public void FlushesOnTheInterval()
    {
        var a = new FakeAnalyst();
        var q = Queue(a, flushS: 0.02);
        q.Push(Row("i", 1));
        Hosts.WaitUntil(() => a.Events.Count > 0);
        Assert.Equal("1", Flat(a));
        q.Stop();
    }

    [Fact]
    public void DrainsInSlicesOf1000()
    {
        var a = new FakeAnalyst();
        var q = Queue(a, maxBatch: 5000, maxQueue: 5000);
        for (var i = 0; i < 1500; i++)
        {
            q.Push(Row("i", i));
        }
        q.Flush();
        Assert.Equal(new[] { 1000, 500 }, a.Events.Select(b => b.Count));
        q.Stop();
    }

    [Fact]
    public void DropsOldestBeyondTheQueueCap()
    {
        var a = new FakeAnalyst();
        var q = Queue(a, maxQueue: 3, maxBatch: 100, flushS: 60);
        for (var i = 0; i < 5; i++)
        {
            q.Push(Row("i", i));
        }
        Assert.Equal(3, q.Size);
        Assert.Equal(2, q.Dropped);
        q.Flush();
        Assert.Equal("2,3,4", Flat(a));
        q.Stop();
    }

    [Fact]
    public void DeadIngestDropsSilentlyAndRecovers()
    {
        var a = new FakeAnalyst { IngestDown = true };
        var q = Queue(a);
        q.Push(Row("i", 1));
        q.Flush();
        Assert.Equal(1, q.Dropped);
        Assert.Equal(0, q.Size);
        a.IngestDown = false;
        q.Push(Row("i", 2));
        q.Flush();
        Assert.Equal("2", Flat(a));
        q.Stop();
    }

    [Fact]
    public void PushNeverThrows()
    {
        var a = new FakeAnalyst();
        var q = Queue(a);
        q.Transport = null!;
        q.Push(Row("i", 1));
        q.Flush();   // a broken transport is swallowed and logged, never thrown
        Assert.Equal(0, q.Size);
        q.Stop();
    }

    [Fact]
    public void AnUnserialisableEventDropsTheBatchNotTheProcess()
    {
        var a = new FakeAnalyst();
        var q = Queue(a);
        q.Push(new Dictionary<string, object?> { ["self"] = new Cyclic() });
        q.Flush();
        Assert.Equal(1, q.Dropped);
        Assert.Empty(a.Events);
        q.Stop();
    }

    private sealed class Cyclic
    {
        public Cyclic Self => this;
    }

    [Fact]
    public void StopEndsTheFlushLoop()
    {
        var a = new FakeAnalyst();
        var q = Queue(a, flushS: 0.01);
        q.Push(Row("i", 1));
        Hosts.WaitUntil(() => a.Events.Count == 1);   // the interval flush ran
        q.Stop();
        q.Push(Row("i", 2));
        Thread.Sleep(50);
        Assert.Single(a.Events);   // nothing flushes on its own after Stop()
    }

    [Fact]
    public async Task AWaitingFlushDrainsBehindTheOneInFlight()
    {
        var a = new FakeAnalyst();
        var gate = new ManualResetEventSlim(false);
        Transport inner = a.Transport;
        var q = Queue(a, maxBatch: 1, flushS: 60);
        q.Transport = req =>
        {
            gate.Wait(2000);   // the periodic flush is mid-POST when the exit drain starts
            return inner(req);
        };
        q.Push(Row("i", 1));
        Hosts.WaitUntil(() => q.InFlight);
        q.Push(Row("i", 2));
        q.Flush();   // the request-path flush yields to the one in flight
        Assert.Empty(a.Events);
        var t = Task.Run(() => q.Drain(budgetS: 2));
        gate.Set();
        await t.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("1|2", Flat(a));
        q.Stop();
    }

    [Fact]
    public void DrainGivesUpAfterItsBudget()
    {
        var a = new FakeAnalyst();
        var q = Queue(a, flushS: 60);
        q.Transport = req =>
        {
            Thread.Sleep(1500);
            return a.Transport(req);
        };
        q.Push(Row("i", 1));
        var t0 = Environment.TickCount64;
        q.Drain(budgetS: 0.1);
        Assert.InRange(Environment.TickCount64 - t0, 0, 1000);   // abandoned, not awaited
        q.Stop();
    }
}

// EnsureFresh checks Due, then takes the single-flight slot: it must re-check Due after taking it (contract §4, v3),
// or a poll that fails in between lets a second one start at once.
using Camada.Snapshot;

namespace Camada.Tests;

public class GateRaceTests
{
    [Fact]
    public void KickThatReadDueBeforeAFailedPollFinishedPollsAgainStraightAway()
    {
        var a = new FakeAnalyst();
        var polls = 0;
        var inFlight = new ManualResetEventSlim(false);
        var releasePoll = new ManualResetEventSlim(false);
        var aInsideDue = new ManualResetEventSlim(false);
        var releaseA = new ManualResetEventSlim(false);
        var fail = false;
        long now = 1_000_000;
        Thread? threadA = null;
        var c = new SnapshotClient("https://analyst.test/snapshot", "snap-test", refreshS: 30, mode: SnapshotMode.Lazy,
            transport: req =>
            {
                if (!fail)
                {
                    return a.Transport(req);
                }
                Interlocked.Increment(ref polls);
                inFlight.Set();
                releasePoll.Wait(5000);
                return new TransportResponse(503, new() { ["retry-after"] = "30" }, Array.Empty<byte>());
            });
        c.Ticks = () =>
        {
            if (Thread.CurrentThread == threadA && !aInsideDue.IsSet)
            {
                aInsideDue.Set();      // A has read _notBefore (still 0) and is inside Stale
                releaseA.Wait(5000);
            }
            return Interlocked.Read(ref now);
        };
        c.Refresh();                                   // warm at t=1000 s
        Interlocked.Exchange(ref now, 1_028_000);      // stale, gate open
        fail = true;
        c.EnsureFresh();                               // poll B starts (503 ra 30)
        Assert.True(inFlight.Wait(5000));
        threadA = new Thread(() => c.EnsureFresh());   // a request thread kicks while B is in flight
        threadA.Start();
        Assert.True(aInsideDue.Wait(5000));
        releasePoll.Set();                             // B finishes: writes _notBefore, releases the slot
        SpinWait.SpinUntil(() => c.Due == false, 5000);
        Thread.Sleep(50);
        releaseA.Set();                                // A resumes: Due already evaluated as true -> Wait(0) succeeds
        threadA.Join(5000);
        Thread.Sleep(200);
        Assert.Equal(1, Volatile.Read(ref polls));     // contract: one poll per gate
    }
}

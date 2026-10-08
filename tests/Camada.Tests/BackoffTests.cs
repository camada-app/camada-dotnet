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
}

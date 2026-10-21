// SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the
// GET /snapshot contract (200 frame + etag + x-camada-config; 304 unchanged; 204 nothing
// published -> enforce nothing). Cold = fail open; any error keeps the previous snapshot.
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Camada.Snapshot;

namespace Camada.Tests;

public class ClientTests
{
    private const string Url = "https://analyst.test/snapshot";
    private static readonly MatchInput Blocked = new() { Ip = FakeAnalyst.BlockedIp };

    private static SnapshotClient Client(FakeAnalyst a, double? refreshS = null, int snapshotVersion = 5) =>
        new(Url, "snap-test", refreshS: refreshS, mode: SnapshotMode.Lazy, transport: a.Transport, sdk: "@camada/dotnet/0.0.0", snapshotVersion: snapshotVersion);

    [Fact]
    public void ColdClientFailsOpen()
    {
        var c = Client(new FakeAnalyst());
        var v = c.Verdict(Blocked);
        Assert.Equal("cold", v.Reason);
        Assert.False(v.Block || v.Challenge || v.Allowed);
    }

    [Fact]
    public void LoadsAndEnforcesWithTheContractHeaders()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        c.Refresh();
        Assert.True(c.Verdict(Blocked).Block);
        var req = a.SnapshotRequests[0];
        Assert.Equal("Bearer snap-test", req.Headers["authorization"]);
        Assert.Equal("@camada/dotnet/0.0.0", req.Headers["x-camada-sdk"]);
        Assert.Equal("5", req.Headers["x-camada-snapshot"]);
        Assert.False(req.Headers.ContainsKey("if-none-match"));
        Assert.Equal("acme", c.Config!.Tenant);
        Assert.Equal(30, c.Config.PollSeconds);
    }

    [Fact]
    public void A304RepeatsConfigAndKeepsTheSnapshot()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        c.Refresh();
        a.Config["beacon"] = false;
        c.Refresh();
        Assert.Equal(a.Etag, a.SnapshotRequests[1].Headers["if-none-match"]);
        Assert.True(c.Verdict(Blocked).Block);
        Assert.False(c.Config!.Beacon);
    }

    [Fact]
    public void A204MeansNothingPublishedAndNotCold()
    {
        var a = new FakeAnalyst { SnapshotStatus = 204 };
        var c = Client(a);
        c.Refresh();
        var v = c.Verdict(Blocked);
        Assert.Null(v.Reason);
        Assert.False(v.Block);
    }

    [Fact]
    public void ErrorsKeepWhatWeHave()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        c.Refresh();
        foreach (var status in new[] { 401, 500 })
        {
            a.SnapshotStatus = status;
            c.Refresh();
            Assert.True(c.Verdict(Blocked).Block);
        }
        a.SnapshotStatus = null;
        a.SnapshotDown = true;
        c.Refresh();
        Assert.True(c.Verdict(Blocked).Block);
    }

    [Fact]
    public void CorruptBodyKeepsThePreviousSnapshot()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        c.Refresh();
        Transport good = a.Transport;
        c.Transport = req =>
        {
            var r = good(req);
            var headers = new Dictionary<string, string>(r.Headers) { ["etag"] = "\"other\"" };
            return new TransportResponse(200, headers, new byte[] { 5, 0, 0, 0 }.Concat("junk!"u8.ToArray()).Concat(new byte[10]).ToArray());
        };
        c.Refresh();
        Assert.True(c.Verdict(Blocked).Block);
    }

    [Fact]
    public void ACorruptFirstBodyIsRetriedAtThePollCadenceNotPerRequest()
    {
        // No good load yet and a 200 the parser rejects: the answer still stamps loaded_at, so the
        // request path (EnsureFresh) does not start a full download per request; the client stays cold.
        var a = new FakeAnalyst();
        var c = Client(a);
        Transport good = a.Transport;
        c.Transport = req =>
        {
            var r = good(req);
            return r with { Body = new byte[] { 5, 0, 0, 0 }.Concat("junk!"u8.ToArray()).Concat(new byte[10]).ToArray() };
        };
        c.EnsureFresh();
        Hosts.WaitUntil(() => a.SnapshotRequests.Count == 1 && !c.Stale);
        for (var i = 0; i < 10; i++)
        {
            c.EnsureFresh();
            Thread.Sleep(10);
        }
        Assert.Single(a.SnapshotRequests);
        Assert.Equal("cold", c.Verdict(Blocked).Reason);
    }

    [Fact]
    public void SameVersionNewEtagReparses()
    {
        // the server ships v3/v4/v5 bodies of one publish under the same meta.version and different etags
        var a = new FakeAnalyst();
        var c = Client(a);
        c.Refresh();
        Assert.False(c.Verdict(new MatchInput { Ip = "192.0.2.20" }).Challenge);   // v3 has no challenge side
        a.Container = "v4";
        c.Refresh();
        Assert.True(c.Verdict(new MatchInput { Ip = "192.0.2.20" }).Challenge);
    }

    [Fact]
    public void SnapshotVersionHeaderFollowsTheOption()
    {
        var a = new FakeAnalyst();
        Client(a, snapshotVersion: 4).Refresh();
        Client(a, snapshotVersion: 3).Refresh();
        Assert.Equal(new[] { "4", "" }, a.SnapshotVersions);
    }

    [Fact]
    public void ServerSteersTheCadenceUnlessPinned()
    {
        var a = new FakeAnalyst();
        a.Config["poll_seconds"] = 7;
        var c = Client(a);
        c.Refresh();
        Assert.Equal(7, c.RefreshS);
        a.Config["poll_seconds"] = 1;   // below the 5 s floor: ignored
        c.Refresh();
        Assert.Equal(7, c.RefreshS);
        var pinned = Client(a, refreshS: 11);
        pinned.Refresh();
        Assert.Equal(11, pinned.RefreshS);
    }

    [Fact]
    public void EnsureFreshIsOffPathAndSingleInFlight()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        c.EnsureFresh();
        c.EnsureFresh();
        Hosts.WaitUntil(() => c.Verdict(new MatchInput { Ip = "0.0.0.0" }).Reason != "cold");
        Assert.True(c.Verdict(Blocked).Block);
        Assert.Single(a.SnapshotRequests);
        c.EnsureFresh();   // fresh: no new poll
        Thread.Sleep(20);
        Assert.Single(a.SnapshotRequests);
    }

    [Fact]
    public void TimerModePollsOnItsOwnAndStops()
    {
        var a = new FakeAnalyst();
        var c = new SnapshotClient(Url, "snap-test", refreshS: 0.02, mode: SnapshotMode.Timer, transport: a.Transport);
        c.Start();
        try
        {
            Hosts.WaitUntil(() => a.SnapshotRequests.Count >= 3);
            Assert.True(a.SnapshotRequests.Count >= 3);
        }
        finally
        {
            c.Stop();
        }
        Thread.Sleep(30);
        var n = a.SnapshotRequests.Count;
        Thread.Sleep(60);
        Assert.Equal(n, a.SnapshotRequests.Count);
    }

    [Fact]
    public void StartIsIdempotentAndStopIsRestartable()
    {
        var a = new FakeAnalyst();
        var c = new SnapshotClient(Url, "snap-test", refreshS: 0.02, mode: SnapshotMode.Timer, transport: a.Transport);
        c.Start();
        c.Start();
        Hosts.WaitUntil(() => a.SnapshotRequests.Count >= 2);
        c.Stop();
        Thread.Sleep(30);
        var n = a.SnapshotRequests.Count;
        c.Start();   // a stopped client can be re-armed (what a host restart does)
        Hosts.WaitUntil(() => a.SnapshotRequests.Count >= n + 2);
        c.Stop();
        Assert.True(a.SnapshotRequests.Count >= n + 2);
    }

    /// <summary>Serves one canned HTTP/1.1 response on loopback. Sync sockets on a dedicated thread, not
    /// HttpListener on Task.Run: a starved thread pool (a loaded machine, the suite's blocked workers) held the
    /// listener's accept past the client's timeout.</summary>
    private static (int Port, Thread Serving) ServeOnce(byte[] head, byte[] body)
    {
        var srv = new TcpListener(IPAddress.Loopback, 0);
        srv.Start();
        var serving = new Thread(() =>
        {
            using var conn = srv.AcceptTcpClient();
            srv.Stop();
            var stream = conn.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            while (!string.IsNullOrEmpty(reader.ReadLine()))
            {
                // skip the request head; the canned response doesn't depend on it
            }
            stream.Write(head);
            stream.Write(body);
        }) { IsBackground = true };
        serving.Start();
        return (((IPEndPoint)srv.LocalEndpoint).Port, serving);
    }

    [Fact]
    public void HttpClientTransportGunzipsAndNeverThrows()
    {
        var payload = FakeAnalyst.Frame("""{"version":"z"}""", "BLK"u8.ToArray());
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(payload);
        }
        var body = ms.ToArray();
        var (port, serving) = ServeOnce(Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nETag: \"z\"\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"), body);
        var r = HttpClientTransport.Send(new TransportRequest("GET", $"http://127.0.0.1:{port}/snapshot", new() { ["accept-encoding"] = "gzip" }, null, 30.0));
        Assert.Equal(200, r.Status);
        Assert.Equal(payload, r.Body);
        Assert.Equal("\"z\"", r.Headers["etag"]);
        Assert.True(serving.Join(TimeSpan.FromSeconds(30)));
        var dead = HttpClientTransport.Send(new TransportRequest("GET", "http://127.0.0.1:1/snapshot", new(), null, 0.2));
        Assert.Equal(0, dead.Status);
    }

    [Fact]
    public void HttpClientTransportKeepsA304WithGzipHeaderAndNoBody()
    {
        var (port, serving) = ServeOnce(Encoding.ASCII.GetBytes(
            "HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nRetry-After: 30\r\nConnection: close\r\n\r\n"), []);
        var r = HttpClientTransport.Send(new TransportRequest("GET", $"http://127.0.0.1:{port}/snapshot", new() { ["accept-encoding"] = "gzip" }, null, 30.0));
        Assert.Equal(304, r.Status);
        Assert.Equal("30", r.Headers["retry-after"]);
        Assert.Empty(r.Body);
        Assert.True(serving.Join(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void NonFinitePollSecondsIsIgnored()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        var before = c.RefreshS;
        Transport good = a.Transport;
        c.Transport = req =>
        {
            var r = good(req);
            var headers = new Dictionary<string, string>(r.Headers) { ["x-camada-config"] = """{"poll_seconds":1e999}""" };   // a timer period of infinity would end the loop
            return r with { Headers = headers };
        };
        c.Refresh();
        Assert.Equal(before, c.RefreshS);
        Assert.True(c.Verdict(Blocked).Block);   // the snapshot itself still loaded
    }

    [Fact]
    public void AMalformedConfigHeaderKeepsThePreviousConfig()
    {
        var a = new FakeAnalyst();
        var c = Client(a);
        c.Refresh();
        Transport good = a.Transport;
        c.Transport = req =>
        {
            var r = good(req);
            return r with { Headers = new Dictionary<string, string>(r.Headers) { ["x-camada-config"] = "[not an object" } };
        };
        c.Refresh();
        Assert.Equal("acme", c.Config!.Tenant);
    }
}

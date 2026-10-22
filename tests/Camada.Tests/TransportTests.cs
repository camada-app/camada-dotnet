// HttpClientTransport against a loopback server. Sync HttpClient.Send on SocketsHttpHandler opens new
// connections via a thread-pool task, so these run alone after the parallel tests (a starved pool stalled them).
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Camada.Snapshot;

namespace Camada.Tests;

[Collection(SerialCollection.Name)]
public class HttpClientTransportTests
{
    /// <summary>Serves one canned HTTP/1.1 response on loopback. Sync sockets on a dedicated thread, not
    /// HttpListener on Task.Run: a starved thread pool (a loaded machine, the suite's blocked workers) held the
    /// listener's accept past the client's timeout.</summary>
    private static (int Port, Thread Serving) ServeOnce(string head, byte[] body)
    {
        var srv = new TcpListener(IPAddress.Loopback, 0);
        srv.Start();
        var serving = new Thread(() =>
        {
            try
            {
                using var conn = srv.AcceptTcpClient();
                srv.Stop();
                var stream = conn.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                while (!string.IsNullOrEmpty(reader.ReadLine()))
                {
                    // skip the request head; the canned response doesn't depend on it
                }
                stream.Write(Encoding.ASCII.GetBytes(head + "Connection: close\r\n\r\n"));
                stream.Write(body);
            }
            catch (Exception e) when (e is IOException or SocketException)
            {
                // client gave up early; an unhandled throw on this thread would kill the test host. The
                // test's status/body asserts still fail on a broken exchange.
            }
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
        var (port, serving) = ServeOnce(
            $"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nETag: \"z\"\r\nContent-Length: {body.Length}\r\n", body);
        var r = HttpClientTransport.Send(new TransportRequest("GET", $"http://127.0.0.1:{port}/snapshot", new() { ["accept-encoding"] = "gzip" }, null, Hosts.PatienceMs / 1000.0));
        Assert.Equal(200, r.Status);
        Assert.Equal(payload, r.Body);
        Assert.Equal("\"z\"", r.Headers["etag"]);
        Assert.True(serving.Join(Hosts.PatienceMs));
        var dead = HttpClientTransport.Send(new TransportRequest("GET", "http://127.0.0.1:1/snapshot", new(), null, 0.2));
        Assert.Equal(0, dead.Status);
    }

    [Fact]
    public void HttpClientTransportKeepsA304WithGzipHeaderAndNoBody()
    {
        var (port, serving) = ServeOnce(
            "HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nRetry-After: 30\r\n", []);
        var r = HttpClientTransport.Send(new TransportRequest("GET", $"http://127.0.0.1:{port}/snapshot", new() { ["accept-encoding"] = "gzip" }, null, Hosts.PatienceMs / 1000.0));
        Assert.Equal(304, r.Status);
        Assert.Equal("30", r.Headers["retry-after"]);
        Assert.Empty(r.Body);
        Assert.True(serving.Join(Hosts.PatienceMs));
    }

    [Fact]
    public void HttpClientTransportReturnsByTheDeadlineWhenTheProxyLookupBlocks()
    {
        // Stands in for macOS's system-proxy lookup, which blocks inside the handler and ignores the token.
        var proxy = new BlockingProxy();
        var spy = new BlockingProxy();
        using var client = HttpClientTransport.Create(proxy);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var r = HttpClientTransport.Send(client, new TransportRequest("GET", "http://127.0.0.1:1/snapshot", new(), null, 0.5));
            sw.Stop();
            Assert.Equal(0, r.Status);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
            Assert.True(proxy.Entered.Wait(Hosts.PatienceMs));   // the send really was stuck in the lookup

            // Once MaxStuck sends are parked on the hung lookup, the next one fails fast without a thread.
            for (var i = 1; i < HttpClientTransport.MaxStuck; i++)
            {
                HttpClientTransport.Send(client, new TransportRequest("GET", "http://127.0.0.1:1/snapshot", new(), null, 0.2));
            }
            using var other = HttpClientTransport.Create(spy);
            sw.Restart();
            Assert.Equal(0, HttpClientTransport.Send(other, new TransportRequest("GET", "http://127.0.0.1:1/snapshot", new(), null, 2.0)).Status);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"took {sw.Elapsed}");
            Assert.False(spy.Entered.IsSet);
        }
        finally
        {
            proxy.Release.Set();
            spy.Release.Set();
            Hosts.WaitUntil(() => HttpClientTransport.Stuck == 0);   // released, the parked sends drain
        }
        Assert.Equal(0, HttpClientTransport.Stuck);
    }

    private sealed class BlockingProxy : IWebProxy
    {
        public readonly ManualResetEventSlim Entered = new();
        public readonly ManualResetEventSlim Release = new();

        public ICredentials? Credentials { get; set; }

        public Uri? GetProxy(Uri destination)
        {
            Entered.Set();
            Release.Wait(Hosts.PatienceMs);
            return null;
        }

        public bool IsBypassed(Uri host) => false;
    }
}

// HttpClientTransport against a loopback server. Sync HttpClient.Send on SocketsHttpHandler opens new
// connections via a thread-pool task, so these run alone after the parallel tests (a starved pool stalled them).
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Camada.Snapshot;

namespace Camada.Tests;

/// <summary>Tests that need an unstarved thread pool or touch process-global state; xUnit runs this collection alone.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class SerialCollection
{
    public const string Name = "serial";
}

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
}

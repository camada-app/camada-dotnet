// The one HTTP seam. The engine, the snapshot client and the event queue speak to the analyst
// through a Transport delegate, so tests inject an in-process fake and production uses
// HttpClient. A transport never throws: a network failure is a status-0 response, which every
// caller treats as "keep what we have".
using System.Net;

namespace Camada;

public sealed record TransportRequest(string Method, string Url, Dictionary<string, string> Headers, byte[]? Body, double TimeoutS);

/// <summary>Status 0 when the request never got an answer; header names are lower-cased.</summary>
public sealed record TransportResponse(int Status, Dictionary<string, string> Headers, byte[] Body);

public delegate TransportResponse Transport(TransportRequest req);

public static class HttpClientTransport
{
    // One client for the process: SocketsHttpHandler pools connections; gzip is decoded transparently
    // (GET /snapshot ships ~5 MB that gzips to a few KB). The per-request timeout rides a token.
    private static readonly HttpClient Client = Create(proxy: null);

    // How long past TimeoutS the caller waits for a send that ignores its token before giving up on it.
    private static readonly TimeSpan Grace = TimeSpan.FromMilliseconds(250);

    // Sends abandoned at their deadline and still stuck. Past the cap the lookup is clearly hung, so we
    // fail fast instead of parking yet another thread on it.
    internal const int MaxStuck = 2;
    private static int _stuck;

    internal static int Stuck => Volatile.Read(ref _stuck);

    /// <summary>Null proxy means the system default (HttpClient.DefaultProxy); tests pass their own.</summary>
    internal static HttpClient Create(IWebProxy? proxy) =>
        new(new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.GZip, Proxy = proxy }) { Timeout = Timeout.InfiniteTimeSpan };

    public static TransportResponse Send(TransportRequest req) => Send(Client, req);

    // On macOS the handler resolves the system proxy (CFNetworkCopySystemProxySettings) synchronously,
    // before any I/O, and that native call ignores the token; under load it has blocked for minutes.
    // So the send runs on its own thread and the caller stops waiting at the deadline: a stuck lookup
    // costs that thread (at most MaxStuck of them), never the snapshot poll or event POST that called us.
    internal static TransportResponse Send(HttpClient client, TransportRequest req)
    {
        try
        {
            if (Stuck >= MaxStuck)
            {
                return Failed();
            }
            var send = Task.Factory.StartNew(() => SendCore(client, req), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            if (send.Wait(TimeSpan.FromSeconds(req.TimeoutS) + Grace))
            {
                return send.Result;
            }
            Interlocked.Increment(ref _stuck);
            send.ContinueWith(_ => Interlocked.Decrement(ref _stuck), TaskScheduler.Default);
            return Failed();
        }
        catch
        {
            return Failed();
        }
    }

    private static TransportResponse Failed() => new(0, new(), Array.Empty<byte>());

    private static TransportResponse SendCore(HttpClient client, TransportRequest req)
    {
        try
        {
            using var msg = new HttpRequestMessage(new HttpMethod(req.Method), req.Url);
            foreach (var (k, v) in req.Headers)
            {
                if (k.Equals("content-type", StringComparison.OrdinalIgnoreCase) || k.Equals("accept-encoding", StringComparison.OrdinalIgnoreCase))
                {
                    continue;   // content-type rides the content; the handler negotiates gzip itself
                }
                msg.Headers.TryAddWithoutValidation(k, v);
            }
            if (req.Body != null)
            {
                msg.Content = new ByteArrayContent(req.Body);
                if (req.Headers.TryGetValue("content-type", out var ct))
                {
                    msg.Content.Headers.TryAddWithoutValidation("content-type", ct);
                }
            }
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(req.TimeoutS));
            using var res = client.Send(msg, HttpCompletionOption.ResponseContentRead, cts.Token);
            var headers = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var h in res.Headers.Concat(res.Content.Headers))
            {
                headers[h.Key.ToLowerInvariant()] = string.Join(", ", h.Value);
            }
            using var ms = new MemoryStream();
            res.Content.ReadAsStream(cts.Token).CopyTo(ms);
            return new TransportResponse((int)res.StatusCode, headers, ms.ToArray());
        }
        catch
        {
            return Failed();
        }
    }
}

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
    private static readonly HttpClient Client = new(new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.GZip }) { Timeout = Timeout.InfiniteTimeSpan };

    public static TransportResponse Send(TransportRequest req)
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
            using var res = Client.Send(msg, HttpCompletionOption.ResponseContentRead, cts.Token);
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
            return new TransportResponse(0, new(), Array.Empty<byte>());
        }
    }
}

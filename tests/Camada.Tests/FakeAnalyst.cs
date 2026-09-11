// An in-process transport standing in for the analyst Worker (GET /snapshot, POST /e): the
// .NET twin of camada-python/tests/fake_analyst.py.
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace Camada.Tests;

public static class Ev
{
    public static string? S(this Dictionary<string, JsonElement> e, string k) =>
        e.TryGetValue(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static long? I(this Dictionary<string, JsonElement> e, string k) =>
        e.TryGetValue(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : null;

    public static bool IsNull(this Dictionary<string, JsonElement> e, string k) =>
        e.TryGetValue(k, out var v) && v.ValueKind == JsonValueKind.Null;

    public static string Json(this IEnumerable<Dictionary<string, JsonElement>> evs) => JsonSerializer.Serialize(evs);
}

public sealed class FakeAnalyst
{
    public const string BlockedIp = "203.0.113.66";      // an ip4 entry in v3-basic and v4-basic
    public const string ChallengedIp = "192.0.2.20";     // a challenge-only ip4 entry in v4-basic
    public const string AllowedIp = "10.0.0.7";          // allow-listed inside the blocked 10.0.0.0/8
    // v5-rules only (§D3): the ordered custom rules the golden container carries.
    public const string RuleBlockedIp = "198.51.100.7";          // builtin:block, a manual-block entry
    public const string SkipPath = "/healthz";                   // cr_00000000000a, skip — beats every side
    public const string RuleBlockedPath = "/api/v2/dump";        // cr_00000000000c, block by path regex
    public const string WarnUa = "Scrapy/2.11 (+https://scrapy.org)";   // cr_00000000000e, warn
    public const string BlockedUa = "curl/8.4.0";                // cr_00000000000f, block
    public const string BlockedHeader = "x-api-key";             // cr_000000000019, `header is` -> block
    public const string BlockedHeaderValue = "leaked-key-1";

    private static readonly Dictionary<string, string> MetaFiles = new() { ["v3"] = "blk3/v3-basic.meta.json", ["v4"] = "blk3/v4-basic.meta.json", ["v5"] = "blk5/v5-rules.meta.json" };
    private static readonly Dictionary<string, string> BinFiles = new() { ["v3"] = "blk3/v3-basic.bin", ["v4"] = "blk3/v4-basic.bin", ["v5"] = "blk5/v5-rules.bin" };

    public List<List<Dictionary<string, JsonElement>>> Events { get; } = new();   // batches POSTed to /e
    public List<string> SdkHeaders { get; } = new();                              // x-camada-sdk seen on /snapshot and /e
    public List<string> SnapshotVersions { get; } = new();                        // x-camada-snapshot seen on /snapshot
    public List<TransportRequest> SnapshotRequests { get; } = new();
    public Dictionary<string, object?> Config { get; set; } = new()
    {
        ["tenant"] = "acme",
        ["beacon"] = true,
        ["sample"] = 1,
        ["exclude"] = Array.Empty<string>(),
        ["trusted_proxy"] = new Dictionary<string, object?> { ["mode"] = "none" },
        ["poll_seconds"] = 30,
    };
    public bool SnapshotDown { get; set; }
    public bool IngestDown { get; set; }
    public int? SnapshotStatus { get; set; }          // force a status (204, 304, 401, 500)
    public string Container { get; set; } = "v3";     // v3 | v4 | v5
    public int IngestStatus { get; set; } = 202;
    private readonly object _lock = new();

    public string MetaJson => File.ReadAllText(Fixtures.PathOf(MetaFiles[Container]));
    public string MetaVersion => JsonDocument.Parse(MetaJson).RootElement.GetProperty("version").GetString()!;
    public byte[] Binary => Fixtures.ReadBin(BinFiles[Container]);
    public string Etag => $"\"{MetaVersion}{(Container == "v3" ? "" : "-" + Container)}\"";
    public string ConfigJson => JsonSerializer.Serialize(Config);

    public static byte[] Frame(string metaJson, byte[] body)
    {
        var m = Encoding.UTF8.GetBytes(metaJson);
        var frame = new byte[4 + m.Length + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)m.Length);
        m.CopyTo(frame, 4);
        body.CopyTo(frame, 4 + m.Length);
        return frame;
    }

    public TransportResponse Transport(TransportRequest req)
    {
        lock (_lock)
        {
            if (req.Url.EndsWith("/snapshot", StringComparison.Ordinal) || req.Url.EndsWith("/e", StringComparison.Ordinal))
            {
                SdkHeaders.Add(req.Headers.GetValueOrDefault("x-camada-sdk", ""));
            }
            if (req.Url.EndsWith("/snapshot", StringComparison.Ordinal))
            {
                SnapshotRequests.Add(req);
                SnapshotVersions.Add(req.Headers.GetValueOrDefault("x-camada-snapshot", ""));
                if (SnapshotDown)
                {
                    return new TransportResponse(0, new(), Array.Empty<byte>());
                }
                var headers = new Dictionary<string, string> { ["x-camada-config"] = ConfigJson, ["cache-control"] = "private, no-store" };
                if (SnapshotStatus is { } forced)
                {
                    return new TransportResponse(forced, headers, Array.Empty<byte>());
                }
                if (req.Headers.GetValueOrDefault("if-none-match") == Etag)
                {
                    return new TransportResponse(304, headers, Array.Empty<byte>());
                }
                headers["etag"] = Etag;
                return new TransportResponse(200, headers, Frame(MetaJson, Binary));
            }
            if (IngestDown)
            {
                return new TransportResponse(0, new(), Array.Empty<byte>());
            }
            if (req.Url.EndsWith("/e", StringComparison.Ordinal))
            {
                Events.Add(JsonSerializer.Deserialize<List<Dictionary<string, JsonElement>>>(req.Body ?? "[]"u8.ToArray())!);
                return new TransportResponse(IngestStatus, new(), Array.Empty<byte>());
            }
            throw new InvalidOperationException("unmocked request: " + req.Url);
        }
    }

    public List<Dictionary<string, JsonElement>> AllEvents
    {
        get
        {
            lock (_lock)
            {
                return Events.SelectMany(b => b).ToList();
            }
        }
    }
}

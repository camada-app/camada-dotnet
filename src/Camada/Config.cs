// Configuration shapes shared by the client and the engine. `ParseKey` splits CAMADA_KEY, and
// `RemoteConfig` is what GET /snapshot hands back in x-camada-config (whitelisted server-side).
using System.Text.Json;

namespace Camada;

/// <summary>Mirrors the server-validated tenant config (edge-analyst src/tenant-config.js):
/// {mode: none} | {mode: hops, hops: N} | {mode: cidrs, cidrs: [...]} | {mode: vercel}.</summary>
public sealed record TrustedProxy(string Mode, int Hops, IReadOnlyList<string>? Cidrs)
{
    public bool Equals(TrustedProxy? other) =>
        other != null && Mode == other.Mode && Hops == other.Hops
        && (Cidrs ?? Array.Empty<string>()).SequenceEqual(other.Cidrs ?? Array.Empty<string>());

    public override int GetHashCode() => HashCode.Combine(Mode, Hops, Cidrs?.Count ?? 0);
}

/// <summary>The parsed x-camada-config header. Every field is optional: the server whitelists what it sends.</summary>
public sealed class RemoteConfig
{
    public string? Tenant { get; init; }
    public bool? Beacon { get; init; }
    public double? Sample { get; init; }
    public IReadOnlyList<string> Exclude { get; init; } = Array.Empty<string>();
    public TrustedProxy? TrustedProxy { get; init; }
    public double? PollSeconds { get; init; }

    /// <summary>Anything but a JSON object is null (callers keep the previous config).</summary>
    public static RemoteConfig? Parse(string raw)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(raw);
        }
        catch (JsonException)
        {
            return null;
        }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            return new RemoteConfig
            {
                Tenant = Str(root, "tenant"),
                Beacon = root.TryGetProperty("beacon", out var b) && (b.ValueKind == JsonValueKind.True || b.ValueKind == JsonValueKind.False) ? b.GetBoolean() : null,
                Sample = Num(root, "sample"),
                Exclude = root.TryGetProperty("exclude", out var ex) && ex.ValueKind == JsonValueKind.Array
                    ? ex.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList()
                    : Array.Empty<string>(),
                TrustedProxy = root.TryGetProperty("trusted_proxy", out var tp) ? Config.TrustedProxyOf(tp) : null,
                PollSeconds = Num(root, "poll_seconds"),
            };
        }
    }

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static double? Num(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;
}

public static class Config
{
    /// <summary>CAMADA_KEY is `&lt;ingest_token&gt;.&lt;snap_token&gt;` (printed by reconcile instructions and seed).</summary>
    public static (string Ingest, string Snap)? ParseKey(string? key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return null;
        }
        var dot = key.IndexOf('.');
        if (dot <= 0 || dot == key.Length - 1)
        {
            return null;
        }
        return (key[..dot], key[(dot + 1)..]);
    }

    /// <summary>CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or malformed returns null,
    /// which callers treat as "defer to the server-delivered tenant config", never as trust.</summary>
    public static TrustedProxy? ParseTrustedProxyEnv(string? v)
    {
        if (string.IsNullOrEmpty(v))
        {
            return null;
        }
        if (v == "none")
        {
            return new TrustedProxy("none", 0, null);
        }
        if (v == "vercel")
        {
            return new TrustedProxy("vercel", 0, null);
        }
        if (v.StartsWith("hops:", StringComparison.Ordinal))
        {
            return int.TryParse(v[5..], out var hops) && hops >= 1 ? new TrustedProxy("hops", hops, null) : null;
        }
        if (v.StartsWith("cidrs:", StringComparison.Ordinal))
        {
            var cidrs = v[6..].Split(',').Select(c => c.Trim()).Where(c => c.Length > 0).ToList();
            return cidrs.Count > 0 ? new TrustedProxy("cidrs", 0, cidrs) : null;
        }
        return null;
    }

    /// <summary>A trusted_proxy object out of the tenant config; anything malformed is null (the peer).</summary>
    internal static TrustedProxy? TrustedProxyOf(JsonElement tp)
    {
        if (tp.ValueKind != JsonValueKind.Object || !tp.TryGetProperty("mode", out var m) || m.ValueKind != JsonValueKind.String)
        {
            return null;
        }
        var mode = m.GetString()!;
        var hops = tp.TryGetProperty("hops", out var h) && h.ValueKind == JsonValueKind.Number && h.TryGetInt32(out var hi) ? hi : 0;
        IReadOnlyList<string>? cidrs = tp.TryGetProperty("cidrs", out var c) && c.ValueKind == JsonValueKind.Array
            ? c.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList()
            : null;
        return new TrustedProxy(mode, hops, cidrs);
    }
}

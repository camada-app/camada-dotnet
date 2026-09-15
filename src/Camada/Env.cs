// Environment wiring. The two-line quickstart depends on this doing the right thing:
//   CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
//   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
//   CAMADA_DISABLED=1                        kill switch, checked at boot and per request
//   CAMADA_SERVERLESS=1                      lazy snapshot mode (no poll loop)
//   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
//   CAMADA_CHALLENGE=0                       do not enforce challenge verdicts
namespace Camada;

public sealed record Env(
    string IngestToken,
    string SnapToken,
    string Secret,                 // HMAC key for the challenge nonce/cookie — never leaves the process
    string IngestUrl,
    string SnapshotUrl,
    bool Serverless,
    TrustedProxy? TrustedProxy)    // null = defer to server-delivered config
{
    // PLACEHOLDER default, the same one @camada/node carries — confirm the production ingest domain before any NuGet publish.
    public const string DefaultIngestUrl = "https://in.camada.app";

    /// <summary>Null (SDK stays inert, one log line) rather than throwing on bad config.</summary>
    public static Env? Resolve(IReadOnlyDictionary<string, string?> env)
    {
        var key = Config.ParseKey(env.GetValueOrDefault("CAMADA_KEY"));
        var ingestToken = key?.Ingest ?? env.GetValueOrDefault("CAMADA_TOKEN");
        var snapToken = key?.Snap ?? env.GetValueOrDefault("CAMADA_SNAPSHOT_TOKEN");
        if (string.IsNullOrEmpty(ingestToken) || string.IsNullOrEmpty(snapToken))
        {
            return null;
        }
        var ingestUrl = (Or(env.GetValueOrDefault("CAMADA_INGEST_URL"), DefaultIngestUrl)).TrimEnd('/');
        return new Env(
            ingestToken,
            snapToken,
            Or(env.GetValueOrDefault("CAMADA_KEY"), $"{ingestToken}.{snapToken}"),
            ingestUrl,
            Or(env.GetValueOrDefault("CAMADA_SNAPSHOT_URL"), $"{ingestUrl}/snapshot"),
            env.GetValueOrDefault("CAMADA_SERVERLESS") == "1",
            Config.ParseTrustedProxyEnv(env.GetValueOrDefault("CAMADA_TRUSTED_PROXY")));
    }

    /// <summary>The process environment as the map Resolve reads.</summary>
    public static IReadOnlyDictionary<string, string?> Process()
    {
        var map = new Dictionary<string, string?>();
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
        {
            map[(string)e.Key] = e.Value as string;
        }
        return map;
    }

    private static string Or(string? v, string fallback) => string.IsNullOrEmpty(v) ? fallback : v;
}

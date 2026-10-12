// The engine's options: everything credential-shaped comes from the environment (Env), never
// from here. Mirrors camada-python's Camada(...) keyword arguments.
namespace Camada;

public sealed class CamadaOptions
{
    /// <summary>Where CAMADA_* are read from; null reads the process environment (per request, for the kill switch).</summary>
    public IReadOnlyDictionary<string, string?>? Env { get; set; }

    /// <summary>The HTTP delegate that reaches the analyst (tests inject a fake); null is HttpClient.</summary>
    public Transport? Transport { get; set; }

    /// <summary>Poll cadence in seconds; set, it is pinned (the server's poll_seconds no longer steers it).</summary>
    public double? RefreshS { get; set; }

    public string ScriptPath { get; set; } = CamadaEngine.DefaultScriptPath;

    public string FpPath { get; set; } = CamadaEngine.DefaultFpPath;

    /// <summary>Enforce `challenge` verdicts with the first-party page (CAMADA_CHALLENGE=0 also switches it off).</summary>
    public bool Challenge { get; set; } = true;

    public string ChallengePath { get; set; } = CamadaEngine.DefaultChallengePath;

    /// <summary>The app listens on a unix socket (Kestrel `ListenUnixSocket`) behind a front end: requests have no
    /// peer, and a cidrs trusted-proxy config walks X-Forwarded-For alone, trusting that front end to have written
    /// it. A Kestrel unix-socket listener is also recognised by its local endpoint. Off (TCP), a request whose
    /// `RemoteIpAddress` is null has an unreadable peer and gets no client ip, never the X-Forwarded-For walk
    /// (contract C6 v3). The decision comes from the listener, never from the shape of the peer.</summary>
    public bool UnixSocketListener { get; set; }

    /// <summary>5 asks for the custom rules too; 4 the sides only; 3 opts out of both.</summary>
    public int SnapshotVersion { get; set; } = Snapshot.SnapshotClient.DefaultSnapshotVersion;
}

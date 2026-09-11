// The challenge kit over the BCL's HMAC-SHA256 and SHA-256, ported from @camada/core
// src/challenge/verify.ts. Synchronous, so the engine's Handle() stays a plain method.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Camada.Challenge;

public sealed class Kit
{
    private readonly byte[] _secret;

    public Kit(string secret) => _secret = Encoding.UTF8.GetBytes(secret);

    private string Hmac(string msg) => Convert.ToHexString(HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(msg))).ToLowerInvariant();

    private string At(string ip, long day) => Hmac(Format.NonceMessage(ip, day))[..Format.NonceHex];

    /// <summary>Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored.</summary>
    public string Nonce(string ip, long nowMs) => At(ip, Format.UtcDay(nowMs));

    // Yesterday still passes: a solve started before midnight UTC must not be thrown away.
    // So one solved (nonce, solution) pair is replayable from its own IP for up to ~48 h,
    // minting a fresh 1 h cookie each time. That is the price of a stateless nonce (§D2) and
    // it is deliberate — do not "fix" it into something that needs shared server state.
    public bool NonceValid(string? ip, long nowMs, string? nonce)
    {
        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(nonce) || nonce.Length != Format.NonceHex)
        {
            return false;
        }
        var day = Format.UtcDay(nowMs);
        return Format.SafeEqual(nonce, At(ip, day)) || Format.SafeEqual(nonce, At(ip, day - 1));
    }

    public string Issue(string ip, long nowMs)
    {
        var exp = nowMs + Format.ChallengeTtlMs;
        return $"{exp.ToString(CultureInfo.InvariantCulture)}.{Hmac(Format.TokenMessage(ip, exp))}";
    }

    // A null ip is refused outright: without one the token is bound to nothing, so a single
    // solve would mint a cookie every other unidentified client could present. Adapters must
    // fail open (serve no challenge) rather than challenge a client they cannot identify.
    public bool TokenValid(string? ip, long nowMs, string? cookieValue)
    {
        if (string.IsNullOrEmpty(ip))
        {
            return false;
        }
        var t = Format.SplitToken(cookieValue);
        if (t == null)
        {
            return false;
        }
        var (exp, mac) = t.Value;
        if (exp <= nowMs || exp > nowMs + Format.ChallengeTtlMs)
        {
            return false;
        }
        return Format.SafeEqual(mac, Hmac(Format.TokenMessage(ip, exp)));
    }

    /// <summary>Proof of work ONLY. Never call it without a passing NonceValid() for the same nonce.</summary>
    public bool SolutionOk(string nonce, string? solution) =>
        Format.SolutionShapeOk(solution)
        && Format.PowOk(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{nonce}.{solution}"))).ToLowerInvariant());

    /// <summary>The whole submission: the nonce is ours and unexpired, and the work is done.</summary>
    public bool Verify(string? ip, long nowMs, string? nonce, string? solution) =>
        NonceValid(ip, nowMs, nonce) && SolutionOk(nonce ?? "", solution);
}

// Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
// raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
// a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
namespace Camada;

public static class Ip
{
    private sealed record Cidr(long Base4, uint[]? Base6, int Bits);   // Base4 is -1 for a v6 cidr

    /// <summary>One X-Forwarded-For entry with any port removed (camada-all-0vho): `[v6]:port` and `[v6]` → v6,
    /// `a.b.c.d:port` → a.b.c.d. A bare IPv6 literal is returned whole (its last group is never a port);
    /// anything else malformed comes back unchanged, so validation rejects it and the peer wins.</summary>
    internal static string StripPort(string e)
    {
        if (e.StartsWith('['))
        {
            var close = e.IndexOf(']');
            if (close == -1)
            {
                return e;
            }
            var inner = e[1..close];
            var rest = e[(close + 1)..];
            return inner.Contains(':') && (rest.Length == 0 || IsPort(rest)) ? inner : e;
        }
        var colon = e.IndexOf(':');
        if (colon == -1 || e.IndexOf(':', colon + 1) != -1)
        {
            return e;   // no colon, or a bare IPv6 literal
        }
        var host = e[..colon];
        return IpParse.ParseIp4(host) >= 0 && IsPort(e[colon..]) ? host : e;
    }

    // `:` then 1-5 ASCII digits (char.IsDigit would also take other scripts' digits)
    private static bool IsPort(string s) => s.Length is >= 2 and <= 6 && s[0] == ':' && s.Skip(1).All(ch => ch is >= '0' and <= '9');

    /// <summary>127.0.0.0/8 or ::1, any spelling. The peer's `::ffff:127.x.x.x` form is already reduced to the dotted quad.</summary>
    private static bool IsLoopback(string ip)
    {
        if (!ip.Contains(':'))
        {
            var n = IpParse.ParseIp4(ip);
            return n >= 0 && n >> 24 == 127;
        }
        return IpParse.ParseIp6(ip) is [0, 0, 0, 1];
    }

    private static bool ValidIp(string s) => s.Contains(':') ? IpParse.ParseIp6(s) != null : IpParse.ParseIp4(s) >= 0;

    private static Cidr? ParseCidr(string c)
    {
        var slash = c.IndexOf('/');
        if (slash == -1)
        {
            return null;
        }
        var addr = c[..slash];
        if (!int.TryParse(c[(slash + 1)..], out var bits))
        {
            return null;
        }
        if (!addr.Contains(':'))
        {
            var b = IpParse.ParseIp4(addr);
            return b >= 0 && bits >= 0 && bits <= 32 ? new Cidr(b, null, bits) : null;
        }
        var words = IpParse.ParseIp6(addr);
        return words != null && bits >= 0 && bits <= 128 ? new Cidr(-1, words, bits) : null;
    }

    private static bool InCidr(string ip, Cidr cidr)
    {
        if (cidr.Base6 == null)
        {
            var n = IpParse.ParseIp4(ip);
            if (n < 0)
            {
                return false;
            }
            var mask = cidr.Bits == 0 ? 0 : 0xFFFFFFFFu << (32 - cidr.Bits);
            return ((uint)n & mask) == ((uint)cidr.Base4 & mask);
        }
        var words = IpParse.ParseIp6(ip);
        if (words == null)
        {
            return false;
        }
        var remaining = cidr.Bits;
        for (var k = 0; k < 4 && remaining > 0; k++)
        {
            var take = Math.Min(32, remaining);
            var mask = take == 32 ? 0xFFFFFFFFu : 0xFFFFFFFFu << (32 - take);
            if ((words[k] & mask) != (cidr.Base6[k] & mask))
            {
                return false;
            }
            remaining -= take;
        }
        return true;
    }

    /// <summary>The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config.
    /// Anything unresolvable falls back to the peer (fail safe).
    /// <para>XFF entries are read without a port (`ip:port`, `[v6]:port`, as Azure writes them) in every mode (camada-all-0vho).</para>
    /// <para>`cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the
    /// right (camada-all-yfc6): if the socket peer is not a trusted proxy, the request did not come through one and
    /// the peer IS the client; XFF is ignored, since anyone hitting the origin directly can write it. A loopback
    /// peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts as a trusted hop: a local front end or sidecar, which no
    /// remote client can be. Loopback is trusted only as the peer, never as an XFF entry. With no peer at all the
    /// walk runs over XFF alone, as before: the host's network edge is trusted to have written it. `hops` and
    /// `vercel` trust XFF by definition and do not look at the peer.</para></summary>
    public static string? ResolveClientIp(string? peer, string? xff, TrustedProxy? cfg)
    {
        var sock = peer != null && peer.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? peer[7..] : peer;   // dual-stack v4-mapped form
        if (cfg == null || cfg.Mode == "none" || string.IsNullOrEmpty(xff))
        {
            return sock;
        }
        var entries = xff.Split(',').Select(e => StripPort(e.Trim())).Where(e => e.Length > 0).ToList();
        if (entries.Count == 0)
        {
            return sock;
        }
        string? candidate = null;
        switch (cfg.Mode)
        {
            case "hops":
                if (cfg.Hops >= 1 && cfg.Hops <= entries.Count)
                {
                    candidate = entries[entries.Count - cfg.Hops];
                }
                break;
            case "vercel":
                candidate = entries[^1];   // Vercel overwrites XFF, so its rightmost entry is trustworthy
                break;
            case "cidrs":
                var trusted = (cfg.Cidrs ?? Array.Empty<string>()).Select(ParseCidr).Where(c => c != null).Cast<Cidr>().ToList();
                if (sock != null && !IsLoopback(sock) && !trusted.Any(t => InCidr(sock, t)))
                {
                    return sock;   // the peer is the first hop: no trusted proxy wrote this XFF
                }
                for (var i = entries.Count - 1; i >= 0; i--)
                {
                    if (!trusted.Any(t => InCidr(entries[i], t)))
                    {
                        candidate = entries[i];
                        break;
                    }
                }
                break;
        }
        return candidate != null && ValidIp(candidate) ? candidate : sock;
    }
}

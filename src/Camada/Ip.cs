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

    /// <summary>A plain IPv4 or IPv6 address (C6 v3), by grammar alone: ASCII hex groups, so embedded dotted quads,
    /// zone ids and brackets fail (IpParse.ParseIp6); a single leading or trailing `:` (`:8:8:8`, `2001:db8::1:`) is
    /// rejected here. Never IPAddress.TryParse, which accepts forms C6 rejects.</summary>
    internal static bool ValidIp(string s)
    {
        if (!s.Contains(':'))
        {
            return IpParse.ParseIp4(s) >= 0;
        }
        var n = s.Length;
        if (n < 2 || (s[0] == ':' && s[1] != ':') || (s[n - 1] == ':' && s[n - 2] != ':'))
        {
            return false;
        }
        return IpParse.ParseIp6(s) != null;
    }

    /// <summary>`::ffff:a.b.c.d` (any case) → a.b.c.d, only when a valid dotted quad follows; anything else is
    /// returned unchanged (`::ffff:7f00:1` stays an ordinary IPv6 address).</summary>
    internal static string Unmap(string s)
    {
        if (s.Length < 14 || !s.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
        {
            return s;
        }
        var v4 = s[7..];
        return IpParse.ParseIp4(v4) >= 0 ? v4 : s;
    }

    /// <summary>Leading and trailing SP and HTAB only (HTTP OWS); never string.Trim(), which removes Unicode whitespace.</summary>
    internal static string TrimOws(string s) => s.Trim(' ', '\t');

    private static bool Trusted(string ip, List<Cidr> trusted) => ValidIp(ip) && trusted.Any(t => InCidr(ip, t));   // a non-IP entry is never a trusted hop

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

    /// <summary>The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config (contract C6 v3).
    /// The result is always a valid IP address or null, in every mode.
    /// <para>XFF entries are trimmed of space and tab only, read without a port (`ip:port`, `[v6]:port`, as Azure
    /// writes them) and with `::ffff:a.b.c.d` reduced to a.b.c.d, in every mode (camada-all-0vho). Several XFF
    /// header lines arrive joined with `, `.</para>
    /// <para>The peer is `RemoteIpAddress` with `::ffff:` removed before a dotted quad, when that is a valid IP; it
    /// is never trimmed or port-stripped. A non-empty peer that is not a valid IP could not be read: the result
    /// falls back to null, never to the XFF walk. Null or empty means no peer (a unix-socket listener).</para>
    /// <para>`cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the
    /// right (camada-all-yfc6): if the socket peer is not a trusted proxy, the request did not come through one and
    /// the peer IS the client; XFF is ignored, since anyone hitting the origin directly can write it. A loopback
    /// peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts as a trusted hop: a local front end or sidecar, which no
    /// remote client can be. Loopback is trusted only as the peer, never as an XFF entry; an XFF entry that is not
    /// a valid IP is never a trusted hop. With no peer at all the walk runs over XFF alone: the host's network edge
    /// is trusted to have written it. `hops` and `vercel` trust XFF by definition and do not look at the peer.</para></summary>
    public static string? ResolveClientIp(string? peer, string? xff, TrustedProxy? cfg)
    {
        var mapped = string.IsNullOrEmpty(peer) ? null : Unmap(peer);   // dual-stack v4-mapped form
        var sock = mapped != null && ValidIp(mapped) ? mapped : null;
        if (cfg == null || cfg.Mode == "none" || string.IsNullOrEmpty(xff))
        {
            return sock;
        }
        var entries = xff.Split(',').Select(e => Unmap(StripPort(TrimOws(e)))).Where(e => e.Length > 0).ToList();
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
                if (mapped != null && (sock == null || (!IsLoopback(sock) && !Trusted(sock, trusted))))
                {
                    return sock;   // the peer is the first hop: no trusted proxy wrote this XFF; an unreadable peer never walks
                }
                for (var i = entries.Count - 1; i >= 0; i--)
                {
                    if (!Trusted(entries[i], trusted))
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

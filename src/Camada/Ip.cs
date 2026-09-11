// Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
// raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
// a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
namespace Camada;

public static class Ip
{
    private sealed record Cidr(long Base4, uint[]? Base6, int Bits);   // Base4 is -1 for a v6 cidr

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
    /// Anything unresolvable falls back to the peer (fail safe).</summary>
    public static string? ResolveClientIp(string? peer, string? xff, TrustedProxy? cfg)
    {
        var sock = peer != null && peer.StartsWith("::ffff:", StringComparison.Ordinal) ? peer[7..] : peer;   // dual-stack v4-mapped form
        if (cfg == null || cfg.Mode == "none" || string.IsNullOrEmpty(xff))
        {
            return sock;
        }
        var entries = xff.Split(',').Select(e => e.Trim()).Where(e => e.Length > 0).ToList();
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

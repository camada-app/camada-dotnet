// Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
// raw X-Forwarded-For is attacker-writable and never trusted without explicit configuration.
namespace Camada.Tests;

public class IpTests
{
    private static TrustedProxy Hops(int n) => new("hops", n, null);
    private static TrustedProxy Cidrs(params string[] c) => new("cidrs", 0, c);

    [Fact]
    public void SocketPeerWithoutConfigEvenWhenXffIsPresent()
    {
        Assert.Equal("10.0.0.1", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66", null));
        Assert.Equal("10.0.0.1", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66", new TrustedProxy("none", 0, null)));
    }

    [Fact]
    public void V4MappedPeerIsUnwrapped()
    {
        Assert.Equal("10.0.0.1", Ip.ResolveClientIp("::ffff:10.0.0.1", null, null));
        Assert.Null(Ip.ResolveClientIp(null, "1.2.3.4", null));
    }

    [Fact]
    public void HopsCountsFromTheRight()
    {
        Assert.Equal("198.51.100.7", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66, 198.51.100.7", Hops(1)));
        Assert.Equal("203.0.113.66", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66, 198.51.100.7", Hops(2)));
        Assert.Equal("10.0.0.1", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66", Hops(2)));   // out of range: the peer
    }

    [Fact]
    public void VercelTakesTheRightmostEntry() =>
        Assert.Equal("203.0.113.66", Ip.ResolveClientIp("10.0.0.1", "spoof, 203.0.113.66", new TrustedProxy("vercel", 0, null)));

    [Fact]
    public void CidrsSkipsTrustedProxiesFromTheRight()
    {
        var cfg = Cidrs("10.0.0.0/8", "2001:db8::/32");
        Assert.Equal("203.0.113.66", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66, 10.1.2.3, 10.9.9.9", cfg));
        Assert.Equal("203.0.113.66", Ip.ResolveClientIp("10.0.0.1", "203.0.113.66, 2001:db8::5", cfg));
        Assert.Equal("10.0.0.1", Ip.ResolveClientIp("10.0.0.1", "10.1.2.3", cfg));               // everything trusted: the peer
        Assert.Equal("10.0.0.1", Ip.ResolveClientIp("10.0.0.1", "not-an-ip, 10.1.2.3", cfg));    // candidate must parse
    }

    /// <summary>The Cloudflare preset as the dashboard stores it (the 22 published ranges).</summary>
    private static readonly string[] Cf =
    {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14",
        "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
    };

    [Fact]
    public void TrialsightsShapeResolvesToTheClient()
    {
        // camada-all-yfc6 Director triage: App Engine's local front end is the socket peer (127.0.0.1)
        // and Google appends 169.254.1.1 after the Cloudflare edge; the client is the entry left of the edge.
        var cfg = Cidrs(Cf.Append("169.254.0.0/16").ToArray());
        Assert.Equal("198.51.100.9", Ip.ResolveClientIp("127.0.0.1", "6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1", cfg));
        Assert.Equal("198.51.100.9", Ip.ResolveClientIp("127.0.0.1", "6.6.6.6, 198.51.100.9, 169.254.1.1", cfg));   // a direct appspot hit
        Assert.Equal("198.51.100.9", Ip.ResolveClientIp("::ffff:127.0.0.1", "6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1", cfg));
    }

    [Fact]
    public void CidrsDirectHitIgnoresAForgedXff()
    {
        // camada-all-yfc6: a peer outside every trusted range did not come through a proxy; it is the client
        var cfg = Cidrs(Cf);
        Assert.Equal("203.0.113.200", Ip.ResolveClientIp("203.0.113.200", "203.0.113.66", cfg));   // framing a victim
        Assert.Equal("203.0.113.200", Ip.ResolveClientIp("203.0.113.200", "8.8.8.8", cfg));        // evading a block
        Assert.Equal("203.0.113.200", Ip.ResolveClientIp("203.0.113.200", "8.8.8.8, 172.64.1.1", cfg));   // a forged edge hop
        Assert.Equal("203.0.113.200", Ip.ResolveClientIp("::FFFF:203.0.113.200", "8.8.8.8", cfg));
        Assert.Equal("198.51.100.9", Ip.ResolveClientIp("172.64.1.1", "1.2.3.4, 198.51.100.9", cfg));   // through the edge: unchanged
        Assert.Equal("198.51.100.9", Ip.ResolveClientIp(null, "1.2.3.4, 198.51.100.9, 172.64.1.1", cfg));   // no peer: the plain walk
        Assert.Equal("127.0.0.1", Ip.ResolveClientIp("172.64.1.1", "127.0.0.1", cfg));   // loopback is trusted only as the peer
    }

    [Fact]
    public void XffEntriesWithAPortResolveToTheAddress()
    {
        // camada-all-0vho: Azure Application Gateway writes ip:port
        Assert.Equal("203.0.113.66", Ip.ResolveClientIp("169.254.130.1", "203.0.113.66:51234", Hops(1)));
        Assert.Equal("2001:db8::66", Ip.ResolveClientIp("169.254.130.1", "[2001:db8::66]:51234", Hops(1)));
        Assert.Equal("2001:db8::66:8080", Ip.ResolveClientIp("169.254.130.1", "2001:db8::66:8080", Hops(1)));   // a bare v6 is never split
        Assert.Equal("203.0.113.66", Ip.ResolveClientIp("169.254.130.1", "203.0.113.66, 169.254.1.1:5000", Cidrs("169.254.0.0/16")));
        Assert.Equal("169.254.130.1", Ip.ResolveClientIp("169.254.130.1", "203.0.113.66:80:90", Hops(1)));   // malformed: the peer
        Assert.Equal("169.254.130.1", Ip.ResolveClientIp("169.254.130.1", "[203.0.113.66]:80", Hops(1)));
    }

    [Fact]
    public void EnvStringForms()
    {
        Assert.Null(Config.ParseTrustedProxyEnv(null));
        Assert.Equal(new TrustedProxy("none", 0, null), Config.ParseTrustedProxyEnv("none"));
        Assert.Equal(new TrustedProxy("vercel", 0, null), Config.ParseTrustedProxyEnv("vercel"));
        Assert.Equal(new TrustedProxy("hops", 2, null), Config.ParseTrustedProxyEnv("hops:2"));
        Assert.Null(Config.ParseTrustedProxyEnv("hops:0"));
        var cidrs = Config.ParseTrustedProxyEnv("cidrs:10.0.0.0/8, 192.0.2.0/24");
        Assert.Equal("cidrs", cidrs!.Mode);
        Assert.Equal(new[] { "10.0.0.0/8", "192.0.2.0/24" }, cidrs.Cidrs);
        Assert.Null(Config.ParseTrustedProxyEnv("cidrs:"));
        Assert.Null(Config.ParseTrustedProxyEnv("bogus"));
    }
}

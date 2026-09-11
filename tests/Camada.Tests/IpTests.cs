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

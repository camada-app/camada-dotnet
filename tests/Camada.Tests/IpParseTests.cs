// Ported from the reference edge-analyst src/blocklist.js parsers: ip4 returns -1 on anything
// unusual; ip6 rejects zone ids and v4-mapped forms. The golden fixtures pin the rest.
namespace Camada.Tests;

public class IpParseTests
{
    [Fact]
    public void Ip4DottedQuadToInt()
    {
        Assert.Equal((203L << 24) | (0L << 16) | (113L << 8) | 66, IpParse.ParseIp4("203.0.113.66"));
        Assert.Equal(0xFFFFFFFFL, IpParse.ParseIp4("255.255.255.255"));
        Assert.Equal(0L, IpParse.ParseIp4("0.0.0.0"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4.5")]
    [InlineData("256.1.1.1")]
    [InlineData("1..2.3")]
    [InlineData("01.2.3.4444")]
    [InlineData("a.b.c.d")]
    [InlineData(" 1.2.3.4")]
    [InlineData("1.2.3.4\n")]
    public void Ip4RejectsAnythingUnusual(string bad) => Assert.Equal(-1L, IpParse.ParseIp4(bad));

    [Fact]
    public void Ip6FullAndCompressedForms()
    {
        Assert.Equal(new uint[] { 0x20010DB8, 0, 0, 1 }, IpParse.ParseIp6("2001:db8::1"));
        Assert.Equal(new uint[] { 0, 0, 0, 1 }, IpParse.ParseIp6("::1"));
        Assert.Equal(new uint[] { 0, 0, 0, 0 }, IpParse.ParseIp6("::"));
        Assert.Equal(new uint[] { 0xFE800000, 0, 0, 1 }, IpParse.ParseIp6("fe80:0:0:0:0:0:0:1"));
        Assert.Equal(new uint[] { 0x20010DB8, 0xCAFE0000, 0, 0 }, IpParse.ParseIp6("2001:DB8:CAFE::"));
    }

    [Theory]
    [InlineData("fe80::1%eth0")]
    [InlineData("::ffff:1.2.3.4")]
    [InlineData("1:2:3:4:5:6:7:8:9")]
    [InlineData("1::2::3")]
    [InlineData("12345::")]
    [InlineData("g::1")]
    [InlineData("1:2:3:4:5:6:7")]
    [InlineData(":1::")]
    public void Ip6RejectsZoneIdsMappedV4AndMalformed(string bad) => Assert.Null(IpParse.ParseIp6(bad));
}

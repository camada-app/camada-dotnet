namespace Camada.Tests;

public class ConfigTests
{
    [Fact]
    public void KeySplitsOnTheFirstDot()
    {
        Assert.Equal(("tok-acme", "snap-acme"), Config.ParseKey("tok-acme.snap-acme"));
        Assert.Equal(("a", "b.c"), Config.ParseKey("a.b.c"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("nodot")]
    [InlineData(".snap")]
    [InlineData("tok.")]
    public void KeyRejectsMissingHalves(string? bad) => Assert.Null(Config.ParseKey(bad));

    [Fact]
    public void RemoteConfigReadsOnlyAJsonObject()
    {
        var cfg = RemoteConfig.Parse("""{"tenant":"acme","beacon":false,"sample":0.5,"exclude":["/health"],"trusted_proxy":{"mode":"hops","hops":2},"poll_seconds":7}""");
        Assert.NotNull(cfg);
        Assert.Equal("acme", cfg!.Tenant);
        Assert.False(cfg.Beacon);
        Assert.Equal(0.5, cfg.Sample);
        Assert.Equal(new[] { "/health" }, cfg.Exclude);
        Assert.Equal(new TrustedProxy("hops", 2, null), cfg.TrustedProxy);
        Assert.Equal(7, cfg.PollSeconds);
        Assert.Null(RemoteConfig.Parse("[1]"));
        Assert.Null(RemoteConfig.Parse("not json"));
        var bare = RemoteConfig.Parse("{}");
        Assert.NotNull(bare);
        Assert.Null(bare!.Beacon);
        Assert.Null(bare.Sample);
        Assert.Null(bare.TrustedProxy);
    }
}

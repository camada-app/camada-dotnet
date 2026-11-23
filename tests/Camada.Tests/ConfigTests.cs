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

    [Theory]
    [InlineData(null, null, false)]
    [InlineData(null, "1", true)]
    [InlineData(null, "true", false)]
    [InlineData(null, " 1", false)]
    [InlineData(false, "1", false)]
    [InlineData(true, null, true)]
    public void TokenHashUsesExplicitOptionOrExactEnvValue(bool? option, string? env, bool expected) =>
        Assert.Equal(expected, Config.ResolveTokenHash(option, env));

    [Theory]
    [InlineData("X-API-KEY", "X-ENV", "x-api-key", false)]
    [InlineData(null, "X-ENV", "x-env", false)]
    [InlineData("", "X-ENV", "x-env", false)]
    [InlineData(null, "", null, false)]
    [InlineData("X-API-KEY", "X-ENV", null, true)]
    [InlineData("X-API-KEY\n", "X-ENV", null, true)]
    [InlineData(" X-API-KEY", "X-ENV", null, true)]
    [InlineData("Authorization", "X-ENV", null, true)]
    [InlineData("COOKIE", "X-ENV", null, true)]
    [InlineData("Set-Cookie", "X-ENV", null, true)]
    [InlineData(null, "Bad:Name", null, true)]
    public void TokenHeaderOnlyAcceptsAsciiNamesAndDoesNotFallBackOnErrors(string? option, string? env, string? expected, bool invalid) =>
        Assert.Equal((expected, invalid), Config.ResolveTokenHeader(option, env));

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

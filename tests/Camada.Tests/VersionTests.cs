// The SDK's wire identity (SDK-03): x-camada-sdk: @camada/dotnet/<version>. The <Version> element
// in Camada.csproj is the single source the build reads and every sibling drift guard parses;
// CamadaVersion.Value repeats it, and this test holds the two together.
using System.Reflection;
using System.Text.RegularExpressions;

namespace Camada.Tests;

public class VersionTests
{
    // edge-analyst src/freshness.js SDK_RE: anything else is silently dropped from sdk_versions.
    private static readonly Regex AnalystSdkRe = new("^@?[a-z0-9._-]+(/[a-z0-9._-]+)?/\\d+\\.\\d+\\.\\d+[a-z0-9.-]*$", RegexOptions.IgnoreCase);

    [Fact]
    public void AssemblyMetadataMatchesTheLiteral()
    {
        var informational = typeof(CamadaEngine).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        Assert.Equal(CamadaVersion.Value, informational.Split('+')[0]);
    }

    [Fact]
    public void TheCsprojVersionElementIsTheLiteral()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Camada.sln")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        var csproj = File.ReadAllText(Path.Combine(dir!.FullName, "src", "Camada", "Camada.csproj"));
        var versions = Regex.Matches(csproj, "<Version>([^<]+)</Version>");
        Assert.Single(versions);   // the drift guards read exactly one
        Assert.Equal(CamadaVersion.Value, versions[0].Groups[1].Value);
    }

    [Fact]
    public void SdkIdIsTheFamilyWireIdentity()
    {
        Assert.Equal($"@camada/dotnet/{CamadaVersion.Value}", CamadaVersion.SdkId);
        Assert.Matches(AnalystSdkRe, CamadaVersion.SdkId);
        Assert.True(CamadaVersion.SdkId.Length <= 64);
    }
}

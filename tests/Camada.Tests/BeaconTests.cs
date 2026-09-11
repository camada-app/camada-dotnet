// The first-party beacon is @camada/browser's auto build, vendored as an embedded resource so the
// package has no runtime file reads. It must be byte-for-byte the sibling's dist/auto.global.js;
// the test fails by name (never skips) when that checkout or its build is missing.
using System.Security.Cryptography;

namespace Camada.Tests;

public class BeaconTests
{
    [Fact]
    public void VendoredBeaconMatchesTheSiblingBuild()
    {
        var dist = Fixtures.BeaconDist();
        Assert.True(File.Exists(dist), $"beacon build missing: {dist} (run npm run build in camada-browser, or set CAMADA_BROWSER_DIST)");
        var src = File.ReadAllBytes(dist);
        Assert.True(src.AsSpan().SequenceEqual(BeaconJs.Bytes), "run scripts/sync-beacon.sh to re-vendor @camada/browser");
        Assert.Equal(Convert.ToHexString(SHA256.HashData(src)).ToLowerInvariant(), BeaconJs.Sha256);
    }

    [Fact]
    public void BeaconNamesItsOwnVersionAndPostsToFp()
    {
        Assert.Contains($"\"{BeaconJs.Version}\"", BeaconJs.Js);
        Assert.Contains("@camada/browser", BeaconJs.Js);
        Assert.Contains("\"fp\"", BeaconJs.Js);   // derives the POST target from the script URL's final segment
    }
}

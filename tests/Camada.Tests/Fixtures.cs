// Shared fixture readers. The golden snapshot containers live in the camada-core sibling checkout
// (copied verbatim from edge-analyst, the format owner); the suite fails by name when they are
// missing rather than skipping, the same stance the web/mkt drift guards take.
using System.Text.Json;

namespace Camada.Tests;

public static class Fixtures
{
    public static readonly string Dir = Locate();

    private static string Locate()
    {
        var env = Environment.GetEnvironmentVariable("CAMADA_FIXTURES_DIR");
        if (!string.IsNullOrEmpty(env))
        {
            return env;
        }
        // walk up from the test binary until a directory containing `camada-core` exists (the workspace root)
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var core = Path.Combine(dir.FullName, "camada-core");
            if (Directory.Exists(core))
            {
                return Path.Combine(core, "test", "fixtures");
            }
            dir = dir.Parent;
        }
        return Path.Combine(AppContext.BaseDirectory, "camada-core", "test", "fixtures");   // a path that fails by name below
    }

    public static string PathOf(string rel)
    {
        var p = Path.Combine(Dir, rel);
        if (!File.Exists(p) && !Directory.Exists(p))
        {
            Assert.Fail($"golden fixture missing: {p} (no camada-core checkout? set CAMADA_FIXTURES_DIR)");
        }
        return p;
    }

    public static byte[] ReadBin(string rel) => File.ReadAllBytes(PathOf(rel));

    public static JsonElement ReadJson(string rel) => JsonDocument.Parse(File.ReadAllText(PathOf(rel))).RootElement;

    /// <summary>The sibling beacon build (or CAMADA_BROWSER_DIST): what Resources/b.js must equal byte for byte.</summary>
    public static string BeaconDist()
    {
        var env = Environment.GetEnvironmentVariable("CAMADA_BROWSER_DIST");
        if (!string.IsNullOrEmpty(env))
        {
            return env;
        }
        var root = Directory.GetParent(Dir)!.Parent!.Parent!.FullName;   // <workspace>/camada-core/test/fixtures -> <workspace>
        return Path.Combine(root, "camada-browser", "dist", "auto.global.js");
    }
}

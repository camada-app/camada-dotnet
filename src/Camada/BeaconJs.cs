// The first-party beacon (@camada/browser's dist/auto.global.js) vendored as an embedded
// resource by scripts/sync-beacon.sh: served at /_cam/b.js with no runtime file read.
// tests/Camada.Tests/BeaconTests.cs pins it to the sibling build byte for byte.
using System.Text;
using System.Text.Json;

namespace Camada;

public static class BeaconJs
{
    public static readonly byte[] Bytes = Resource("Camada.Resources.b.js");
    public static readonly string Js = Encoding.UTF8.GetString(Bytes);
    public static readonly string Version;
    public static readonly string Sha256;

    static BeaconJs()
    {
        using var doc = JsonDocument.Parse(Resource("Camada.Resources.beacon.json"));
        Version = doc.RootElement.GetProperty("version").GetString() ?? "";
        Sha256 = doc.RootElement.GetProperty("sha256").GetString() ?? "";
    }

    private static byte[] Resource(string name)
    {
        using var s = typeof(BeaconJs).Assembly.GetManifestResourceStream(name) ?? throw new InvalidOperationException("missing embedded resource " + name);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}

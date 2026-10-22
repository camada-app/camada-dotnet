// On macOS, each HttpClient request through the default proxy asks CFNetworkCopySystemProxySettings for the
// system proxy: a blocking native call no CancellationToken or HttpClient.Timeout interrupts. On a loaded machine
// it stalled for minutes, so the HttpClientTransport and real-Kestrel tests blew past their bounds. Every request
// in the suite stays on the machine (loopback or a unix socket), so the suite goes direct.
using System.Net;
using System.Runtime.CompilerServices;

namespace Camada.Tests;

internal static class DirectHttp
{
    [ModuleInitializer]
    internal static void NoSystemProxy() => HttpClient.DefaultProxy = new WebProxy();
}

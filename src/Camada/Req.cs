// What an adapter hands the engine. Header names are lower-cased; the list keeps the order the
// host gave (ASP.NET Core's header dictionary, which does not promise wire order).
namespace Camada;

public sealed class Req
{
    public string Method { get; init; } = "GET";
    public string Path { get; init; } = "/";                 // no query
    public string Query { get; init; } = "";                 // with the leading '?', or ''
    public string Host { get; init; } = "";
    public string? HttpVersion { get; init; }
    public string? Peer { get; init; }                       // the socket peer the host vouches for
    public bool Https { get; init; }
    public IList<KeyValuePair<string, string>> Headers { get; init; } = new List<KeyValuePair<string, string>>();
    public string? Route { get; set; }                       // the matched route pattern, when the host knows it at finish time

    /// <summary>A header the client repeated is joined the way node:http does it: cookies with '; ' (HTTP/2
    /// clients split them into several fields; CookieValue() looks for '; name='), the rest with ', '.</summary>
    public string? Header(string name)
    {
        List<string>? vals = null;
        foreach (var (k, v) in Headers)
        {
            if (k == name)
            {
                (vals ??= new List<string>()).Add(v);
            }
        }
        return vals == null ? null : string.Join(name == "cookie" ? "; " : ", ", vals);
    }
}

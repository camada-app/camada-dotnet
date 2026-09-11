// The per-request context the middleware stores in HttpContext.Items["camada"]: what the app
// reads (rid, sid, ip) and what the helpers resolve through (the request and its engine).
namespace Camada;

public sealed class CamadaContext
{
    internal CamadaContext(string rid, string sid, string? ip, Req req, CamadaEngine engine)
    {
        Rid = rid;
        Sid = sid;
        Ip = ip;
        Req = req;
        Engine = engine;
    }

    public string Rid { get; }
    public string Sid { get; }
    public string? Ip { get; }
    internal Req Req { get; }
    internal CamadaEngine Engine { get; }
    internal bool Challenged { get; set; }   // ServeChallenge() answered from inside the app: its event already shipped
}

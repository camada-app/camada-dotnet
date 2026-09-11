// The adapter contract's answer: an Answer means camada fully answered the request (block,
// challenge, verify, beacon endpoints); a Passed means run the app, stamp the rid header and
// session cookie on its response, and call OnFinish(status) once when it is done.
namespace Camada;

public abstract record Result;

/// <summary>camada answered the request; the adapter writes exactly this.</summary>
public sealed record Answer(int Status, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body) : Result;

/// <summary>Run the app. Rid/SetCookie ride the response; Ctx is stored on the host request
/// (HttpContext.Items["camada"]); OnFinish(status) is called once at the end.</summary>
public sealed record Passed(string? Rid, string? SetCookie, CamadaContext? Ctx, Action<int>? OnFinish) : Result
{
    public static readonly Passed Inert = new(null, null, null, null);
}

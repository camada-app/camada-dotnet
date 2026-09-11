// The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of
// the SDK catches, falls back, and reports through LogRateLimited(): at most one line a minute.
namespace Camada;

public static class Guarded
{
    private static long _lastLog;   // Environment.TickCount64 of the last line, 0 = never

    /// <summary>Where the one line a minute goes. Defaults to stderr; AddCamada() points it at ILogger.</summary>
    public static Action<string> Sink { get; set; } = line => Console.Error.WriteLine(line);

    public static void LogRateLimited(object err)
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastLog);
        if (last != 0 && now - last < 60_000)
        {
            return;
        }
        Interlocked.Exchange(ref _lastLog, now);
        try
        {
            // the message only, never a stack trace: a suppressed error must not read like a crash in the host's log
            var text = err is Exception ex ? $"{ex.GetType().Name}: {ex.Message}" : err.ToString();
            Sink($"[camada] suppressed error (SDK fails open): {text}");
        }
        catch
        {
            // even logging must not throw
        }
    }

    /// <summary>Tests only: forget the last line so the next one is not suppressed.</summary>
    internal static void ResetForTests() => Interlocked.Exchange(ref _lastLog, 0);
}

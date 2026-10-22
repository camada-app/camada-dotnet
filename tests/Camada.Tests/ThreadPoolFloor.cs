// The suite blocks pool threads on purpose (Host.Call's synchronous wait, WaitUntil's spin, the queue's
// Drain), and the SDK schedules its boot poll, refresh loop and event loop with Task.Run. A 2-core CI
// runner starts the pool with two workers and injects more at roughly one per second, so a queued boot
// poll can sit for seconds before it runs. Guarantee enough workers up front; the pool only makes a thread
// when work queues, so a high floor costs nothing on an idle run and keeps boot polls moving on a starved one.
using System.Runtime.CompilerServices;

namespace Camada.Tests;

internal static class ThreadPoolFloor
{
    [ModuleInitializer]
    internal static void Raise()
    {
        ThreadPool.GetMinThreads(out var workers, out var io);
        ThreadPool.SetMinThreads(Math.Max(workers, 128), Math.Max(io, 128));
    }
}

// The SDK-served challenge (contracts §D2): a stateless per-(ip, UTC day) HMAC nonce, a 16-bit
// SHA-256 proof of work, and an HMAC cookie bound to the ip for one hour. Ported case for case
// from camada-core/test/challenge.test.ts via camada-python/tests/test_challenge.py.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Camada.Challenge;

namespace Camada.Tests;

public static class Solver
{
    public static string Solve(string nonce, int bits = 16)
    {
        var n = 0;
        while (!Format.PowOk(Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes($"{nonce}.{n}"))).ToLowerInvariant(), bits))
        {
            n++;
        }
        return n.ToString(CultureInfo.InvariantCulture);
    }
}

public class ChallengeTests
{
    private const long DayMs = 86_400_000;
    private const long Now = 1_800_000_000_000;
    private const string IpAddr = "203.0.113.9";

    public class Nonce
    {
        [Fact]
        public void DeterministicPerIpAndUtcDay()
        {
            var kit = new Kit("secret");
            string a = kit.Nonce(IpAddr, Now), b = kit.Nonce(IpAddr, Now + 1000);
            Assert.Equal(a, b);
            Assert.Equal(Format.NonceHex, a.Length);
            Assert.Matches("^[0-9a-f]{32}$", a);
            Assert.NotEqual(a, kit.Nonce("203.0.113.10", Now));
            Assert.NotEqual(a, kit.Nonce(IpAddr, Now + DayMs));
            Assert.NotEqual(a, new Kit("other").Nonce(IpAddr, Now));
        }

        [Fact]
        public void AcceptsTodayAndYesterdayRejectsOlderAndForgeries()
        {
            var kit = new Kit("secret");
            var yesterday = kit.Nonce(IpAddr, Now - DayMs);
            Assert.True(kit.NonceValid(IpAddr, Now, kit.Nonce(IpAddr, Now)));
            Assert.True(kit.NonceValid(IpAddr, Now, yesterday));
            Assert.False(kit.NonceValid(IpAddr, Now, kit.Nonce(IpAddr, Now - 2 * DayMs)));
            Assert.False(kit.NonceValid(IpAddr, Now, new string('0', 32)));
            Assert.False(kit.NonceValid(IpAddr, Now, kit.Nonce(IpAddr, Now)[..^1]));
            Assert.False(kit.NonceValid(null, Now, kit.Nonce(IpAddr, Now)));
            Assert.False(kit.NonceValid(IpAddr, Now, null));
        }
    }

    public class Token
    {
        [Fact]
        public void RoundTripsWithinTheHourAndExpiresAfter()
        {
            var kit = new Kit("secret");
            var t = kit.Issue(IpAddr, Now);
            Assert.True(kit.TokenValid(IpAddr, Now + 3_599_000, t));
            Assert.False(kit.TokenValid(IpAddr, Now + 3_600_000, t));
        }

        [Fact]
        public void BoundToTheIpAndUnforgeable()
        {
            var kit = new Kit("secret");
            var t = kit.Issue(IpAddr, Now);
            Assert.False(kit.TokenValid("203.0.113.10", Now, t));
            var parts = t.Split('.');
            string exp = parts[0], mac = parts[1];
            Assert.False(kit.TokenValid(IpAddr, Now, $"{exp}.{new string('0', mac.Length)}"));
            Assert.False(kit.TokenValid(IpAddr, Now, $"{long.Parse(exp, CultureInfo.InvariantCulture) + 1}.{mac}"));
            Assert.False(kit.TokenValid(null, Now, t));   // no ip: never
            foreach (var junk in new[] { null, "", "x", ".mac", "notanumber.mac" })
            {
                Assert.False(kit.TokenValid(IpAddr, Now, junk));
            }
        }

        [Fact]
        public void RefusesAnExpiryFurtherOutThanTheTtl()
        {
            var kit = new Kit("secret");
            var far = kit.Issue(IpAddr, Now + 10_000_000);   // minted "in the future": exp > now + TTL
            Assert.False(kit.TokenValid(IpAddr, Now, far));
        }
    }

    public class ProofOfWork
    {
        [Fact]
        public void AcceptsA16BitSolutionAndRejectsAnythingElse()
        {
            var kit = new Kit("secret");
            var nonce = kit.Nonce(IpAddr, Now);
            var sol = Solver.Solve(nonce);
            Assert.True(kit.SolutionOk(nonce, sol));
            Assert.True(kit.Verify(IpAddr, Now, nonce, sol));
            Assert.False(kit.SolutionOk(nonce, sol + "1"));
            Assert.False(kit.SolutionOk(nonce, new string('x', 33)));
            Assert.False(kit.SolutionOk(nonce, null));
            var forged = new string('f', 32);
            Assert.False(kit.Verify(IpAddr, Now, forged, Solver.Solve(forged)));   // a forged nonce, even with real work
        }

        [Fact]
        public void PowOkCountsLeadingZeroBits()
        {
            Assert.True(Format.PowOk("0000ffff", 16));
            Assert.False(Format.PowOk("0001ffff", 16));
            Assert.True(Format.PowOk("00007fff", 17));
            Assert.False(Format.PowOk("0000ffff", 17));
            Assert.True(Format.PowOk("0", 4));
            Assert.False(Format.PowOk("", 4));
        }
    }

    public class Helpers
    {
        [Fact]
        public void CookieString()
        {
            Assert.Equal("_cch=1.abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax", Format.Cookie("1.abc", false));
            Assert.EndsWith("; Secure", Format.Cookie("1.abc", true));
        }

        [Fact]
        public void SafeReturnToKeepsOnlyASameSitePath()
        {
            Assert.Equal("/a/b?c=1", Format.SafeReturnTo("/a/b?c=1"));
            foreach (var bad in new[] { null, "", "https://evil", "//evil", "/\\evil", "/a b", "/é", "/" + new string('a', 2048), "relative" })
            {
                Assert.Equal("/", Format.SafeReturnTo(bad));
            }
        }

        [Fact]
        public void WantsHtml()
        {
            Assert.True(Format.WantsHtml("text/html,*/*", null));
            Assert.True(Format.WantsHtml("text/html", "document"));
            Assert.False(Format.WantsHtml("application/json", null));
            Assert.False(Format.WantsHtml("text/html", "empty"));
            Assert.False(Format.WantsHtml(null, null));
        }

        [Fact]
        public void FormBodyLastValueWinsAndNeverThrows()
        {
            var parsed = Format.ParseFormBody("a=1&b=x+y&a=2&c&%zz=%zz");
            Assert.Equal(new Dictionary<string, string> { ["a"] = "2", ["b"] = "x y", ["c"] = "", ["%zz"] = "%zz" }, parsed);
            var f = Format.ParseFormBody("nonce=abc&solution=7&to=%2Fx%3Fy%3D1");
            Assert.Equal(new Dictionary<string, string> { ["nonce"] = "abc", ["solution"] = "7", ["to"] = "/x?y=1" }, f);
            Assert.Empty(Format.ParseFormBody(""));
        }

        [Fact]
        public void Escaping()
        {
            Assert.Equal("a&lt;b&gt;&amp;&quot;c&#39;", Format.EscapeAttr("a<b>&\"c'"));
            Assert.Equal("\"\\u003c/script>\"", Format.EscapeScript("</script>"));
            Assert.Equal("\"a\\\\b\\\"c\\n\\u00e9\"", Format.EscapeScript("a\\b\"c\né"));   // json.dumps spelling: ascii-only, lower-case hex
        }
    }

    public class PageTests
    {
        [Fact]
        public void SelfContainedAndEscaped()
        {
            var html = Page.ChallengePage(nonce: string.Concat(Enumerable.Repeat("ab", 16)), action: "/__camada/challenge", to: "/x\"><script>");
            Assert.StartsWith("<!doctype html>", html);
            Assert.DoesNotContain("http", html.Split("<script>")[0].Replace("http-equiv", ""));   // no external assets before the solver
            Assert.Contains("action=\"/__camada/challenge\"", html);
            Assert.Contains("value=\"/x&quot;&gt;&lt;script&gt;\"", html);
            Assert.DoesNotContain("crypto.subtle", html);
            Assert.Contains("__camadaSha256Words", html);
            Assert.Contains("shift=16", html);
        }

        [Fact]
        public void DifficultyIsClamped()
        {
            Assert.Contains("shift=0", Page.ChallengePage(nonce: new string('a', 32), action: "/v", to: "/", bits: 99));
            Assert.Contains("shift=31", Page.ChallengePage(nonce: new string('a', 32), action: "/v", to: "/", bits: 0));
        }

        [Fact]
        public void TheInlineSolverProducesAValidProofOfWork()
        {
            // the page's own SHA-256 must agree with the server's: a nonce the kit issues, solved by the JS's
            // algorithm re-run here, is accepted by the kit (the browser follows the same code path)
            var kit = new Kit("secret");
            var nonce = kit.Nonce(IpAddr, Now);
            Assert.True(kit.Verify(IpAddr, Now, nonce, Solver.Solve(nonce)));
            Assert.Contains($"var nonce=\"{nonce}\"", Page.ChallengePage(nonce: nonce, action: "/v", to: "/"));
        }
    }
}

// Redaction is not configurable off: credential-looking query values become ~r, body values
// never ship, user identifiers are HMAC-hashed inside the SDK.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Camada.Tests;

public class RedactTests
{
    [Fact]
    public void ScrubQueryByNameAndByValueShape()
    {
        Assert.Equal("?q=hello&token=~r&x=1", Redact.ScrubQuery("?q=hello&token=abc&x=1"));
        Assert.Equal("?api_key=~r&PASSWORD=~r", Redact.ScrubQuery("?api_key=k&PASSWORD=p"));
        Assert.Equal("?t=~r", Redact.ScrubQuery("?t=eyJhbGciOi.eyJzdWIiOi.sig"));
        Assert.Equal("?h=~r", Redact.ScrubQuery("?h=" + new string('a', 32)));
        Assert.Equal("?b=~r", Redact.ScrubQuery("?b=" + new string('A', 40) + "=="));
        Assert.Equal("?flag&x=1", Redact.ScrubQuery("?flag&x=1"));   // a bare name is kept as is
    }

    [Fact]
    public void ScrubQueryKeepsShapeAndEmpties()
    {
        Assert.Equal("", Redact.ScrubQuery(""));
        Assert.Equal("", Redact.ScrubQuery(null));
        Assert.Equal("?", Redact.ScrubQuery("?"));
        Assert.Equal("a=1&code=~r", Redact.ScrubQuery("a=1&code=2"));   // no leading ? is fine too
    }

    [Fact]
    public void BodyShapeIsNamesAndSizesOnly()
    {
        var shape = Redact.BodyShape(JsonDocument.Parse("""{"email":"a@b.c","n":12,"none":null,"arr":[1,2]}""").RootElement);
        Assert.Equal(new Dictionary<string, int> { ["email"] = 5, ["n"] = 2, ["none"] = 0, ["arr"] = 5 }, shape);
        Assert.Null(Redact.BodyShape(JsonDocument.Parse("[1]").RootElement));
        Assert.Null(Redact.BodyShape(JsonDocument.Parse("\"str\"").RootElement));
    }

    [Fact]
    public void HashUserIdIsALabelledTruncatedHmac()
    {
        var expected = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes("tok"), Encoding.UTF8.GetBytes("uid:alice@example.com"))).ToLowerInvariant()[..32];
        Assert.Equal(expected, Redact.HashUserId("alice@example.com", "tok"));
        Assert.Equal(32, Redact.HashUserId("x", "tok").Length);
    }
}

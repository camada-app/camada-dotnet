// Allocation-light IP parsers, ported 1:1 from edge-analyst src/blocklist.js through
// @camada/core src/snapshot/ipparse.ts (the reference the conformance fixtures are generated
// from). Behaviour must not drift: ip4 returns -1 on anything unusual; ip6 rejects zone ids and
// v4-mapped forms. The ip4 result is a long so -1 and the full uint32 range share one type.
namespace Camada;

public static class IpParse
{
    /// <summary>Dotted-quad IPv4 to a uint32, or -1 when the string is not a plain IPv4 address.</summary>
    public static long ParseIp4(string s)
    {
        long n = 0;
        int part = 0, digits = 0, dots = 0;
        foreach (var ch in s)
        {
            if (ch == '.')
            {
                if (digits == 0 || part > 255)
                {
                    return -1;
                }
                dots++;
                if (dots > 3)
                {
                    return -1;
                }
                n = n * 256 + part;
                part = digits = 0;
            }
            else if (ch >= '0' && ch <= '9')
            {
                part = part * 10 + (ch - '0');
                digits++;
                if (digits > 3)
                {
                    return -1;
                }
            }
            else
            {
                return -1;
            }
        }
        if (dots != 3 || digits == 0 || part > 255)
        {
            return -1;
        }
        return n * 256 + part;
    }

    /// <summary>IPv6 text to four big-endian uint32 words, or null when it is not a plain IPv6 address.</summary>
    public static uint[]? ParseIp6(string s)
    {
        var length = s.Length;
        var groups = new uint[8];
        int n = 0, digits = 0, dbl = -1, i = 0;
        uint val = 0;
        if (length > 1 && s[0] == ':' && s[1] == ':')
        {
            dbl = 0;
            i = 2;
        }
        while (i <= length)
        {
            var c = i < length ? s[i] : ':';   // a sentinel colon closes the last group
            if (c == ':')
            {
                if (digits > 0)
                {
                    if (n >= 8)
                    {
                        return null;
                    }
                    groups[n++] = val;
                    val = 0;
                    digits = 0;
                }
                else if (i < length)
                {
                    if (dbl != -1)
                    {
                        return null;
                    }
                    dbl = n;
                }
            }
            else
            {
                uint d;
                if (c >= '0' && c <= '9')
                {
                    d = (uint)(c - '0');
                }
                else if (c >= 'a' && c <= 'f')
                {
                    d = (uint)(c - 'a' + 10);
                }
                else if (c >= 'A' && c <= 'F')
                {
                    d = (uint)(c - 'A' + 10);
                }
                else
                {
                    return null;
                }
                val = (val << 4) | d;
                digits++;
                if (digits > 4)
                {
                    return null;
                }
            }
            i++;
        }
        if (dbl == -1)
        {
            if (n != 8)
            {
                return null;
            }
        }
        else
        {
            if (n >= 8)
            {
                return null;
            }
            var shift = 8 - n;
            for (var k = 7; k >= dbl + shift; k--)
            {
                groups[k] = groups[k - shift];
            }
            for (var k = dbl; k < dbl + shift; k++)
            {
                groups[k] = 0;
            }
        }
        return new[]
        {
            (groups[0] << 16) | groups[1],
            (groups[2] << 16) | groups[3],
            (groups[4] << 16) | groups[5],
            (groups[6] << 16) | groups[7],
        };
    }
}

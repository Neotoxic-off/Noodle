namespace Noodle.Core.Services;

public static class EntropyCalculator
{
    public static double Calculate(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;
        var freq = new int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0;
        double len = data.Length;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = f / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}

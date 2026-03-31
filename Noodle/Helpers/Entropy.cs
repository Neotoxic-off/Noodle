using System;
using System.Collections.Generic;
using System.Text;

namespace Noodle.Library.Helpers
{
    public class Entropy
    {
        public static double Get(byte[] data)
        {
            double entropy = 0.0;
            int length = data.Length;
            int[] counts = new int[256];

            if (data is not null && length > 0)
            {
                foreach (byte b in data)
                {
                    counts[b]++;
                }

                for (int i = 0; i < 256; i++)
                {
                    if (counts[i] == 0)
                        continue;

                    double p = (double)counts[i] / length;
                    entropy -= p * Math.Log(p, 2);
                }

            }

            return entropy;
        }
    }
}

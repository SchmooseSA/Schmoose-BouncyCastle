using Org.BouncyCastle.Bcpg;

namespace Org.BouncyCastle.bcpg
{
    public class Random : System.Random, IRandom
    {
        public Random() { }

        public Random(int seed)
            : base(seed) { }
    }
}

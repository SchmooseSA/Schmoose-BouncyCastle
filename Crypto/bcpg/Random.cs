namespace Org.BouncyCastle.Bcpg
{
    public class Random : System.Random, IRandom
    {
        public Random() { }

        public Random(int seed)
            : base(seed) { }
    }
}

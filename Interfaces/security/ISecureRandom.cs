using Org.BouncyCastle.Bcpg;

namespace Org.BouncyCastle.Security
{
    public interface ISecureRandom : IRandom
    {
        byte[] GenerateSeed(
            int length);

        void SetSeed(
            byte[] inSeed);

        void SetSeed(
            long seed);

        void NextBytes(
            byte[] buffer,
            int start,
            int length);

        int NextInt();
        long NextLong();
    }
}
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    public interface IKeyGenerationParameters
    {
        ISecureRandom Random { get; }
        int Strength { get; }
    }
}
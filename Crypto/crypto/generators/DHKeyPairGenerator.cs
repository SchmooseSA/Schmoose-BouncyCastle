using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * a Diffie-Hellman key pair generator.
     *
     * This generates keys consistent for use in the MTI/A0 key agreement protocol
     * as described in "Handbook of Applied Cryptography", Pages 516-519.
     */
    public class DHKeyPairGenerator
		: IAsymmetricCipherKeyPairGenerator
    {
		private DHKeyGenerationParameters param;

		public virtual void Init(
			IKeyGenerationParameters parameters)
        {
            this.param = (DHKeyGenerationParameters)parameters;
        }

		public virtual IAsymmetricCipherKeyPair GenerateKeyPair()
        {
			DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.Instance;
			DHParameters dhp = param.Parameters;

            IBigInteger x = helper.CalculatePrivate(dhp, param.Random);
            IBigInteger y = helper.CalculatePublic(dhp, x);

			return new AsymmetricCipherKeyPair(
                new DHPublicKeyParameters(y, dhp),
                new DHPrivateKeyParameters(x, dhp));
        }
    }
}

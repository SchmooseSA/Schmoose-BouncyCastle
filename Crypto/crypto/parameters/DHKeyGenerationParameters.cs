using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DHKeyGenerationParameters : KeyGenerationParameters
    {
        private readonly DHParameters _parameters;

        public DHKeyGenerationParameters(ISecureRandom random, DHParameters parameters)
            : base(random, GetStrength(parameters))
        {
            _parameters = parameters;
        }

        public DHParameters Parameters
        {
            get { return _parameters; }
        }

        internal static int GetStrength(DHParameters parameters)
        {
            return parameters.L != 0 ? parameters.L : parameters.P.BitLength;
        }
    }
}

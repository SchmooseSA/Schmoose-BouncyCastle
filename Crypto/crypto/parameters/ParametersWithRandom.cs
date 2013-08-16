using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithRandom : ICipherParameters
    {
        private readonly ICipherParameters _parameters;
        private readonly ISecureRandom _random;

        public ParametersWithRandom(ICipherParameters parameters, ISecureRandom random)
        {
            if (parameters == null)
                throw new ArgumentNullException("random");
            if (random == null)
                throw new ArgumentNullException("random");

           _parameters = parameters;
           _random = random;
        }

        public ParametersWithRandom(ICipherParameters parameters)
            : this(parameters, new SecureRandom())
        {
        }

        [Obsolete("Use Random property instead")]
        public ISecureRandom GetRandom()
        {
            return Random;
        }

        public ISecureRandom Random
        {
            get { return _random; }
        }

        public ICipherParameters Parameters
        {
            get { return _parameters; }
        }
    }
}

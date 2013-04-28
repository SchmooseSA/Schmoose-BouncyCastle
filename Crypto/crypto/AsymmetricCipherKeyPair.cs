using System;

namespace Org.BouncyCastle.Crypto
{
    /**
     * a holding class for public/private parameter pairs.
     */
    public class AsymmetricCipherKeyPair : IAsymmetricCipherKeyPair
    {
        private readonly IAsymmetricKeyParameter _publicParameter;
        private readonly IAsymmetricKeyParameter _privateParameter;

        /**
         * basic constructor.
         *
         * @param publicParam a public key parameters object.
         * @param privateParam the corresponding private key parameters.
         */
        public AsymmetricCipherKeyPair(IAsymmetricKeyParameter publicParameter, IAsymmetricKeyParameter privateParameter)
        {
            if (publicParameter.IsPrivate)
                throw new ArgumentException("Expected a public key", "publicParameter");
            if (!privateParameter.IsPrivate)
                throw new ArgumentException("Expected a private key", "privateParameter");

            _publicParameter = publicParameter;
            _privateParameter = privateParameter;
        }

        /**
         * return the public key parameters.
         *
         * @return the public key parameters.
         */
        public IAsymmetricKeyParameter Public
        {
            get { return _publicParameter; }
        }

        /**
         * return the private key parameters.
         *
         * @return the private key parameters.
         */
        public IAsymmetricKeyParameter Private
        {
            get { return _privateParameter; }
        }
    }
}

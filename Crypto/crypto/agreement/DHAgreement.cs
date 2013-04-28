using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /**
     * a Diffie-Hellman key exchange engine.
     * <p>
     * note: This uses MTI/A0 key agreement in order to make the key agreement
     * secure against passive attacks. If you're doing Diffie-Hellman and both
     * parties have long term public keys you should look at using this. For
     * further information have a look at RFC 2631.</p>
     * <p>
     * It's possible to extend this to more than two parties as well, for the moment
     * that is left as an exercise for the reader.</p>
     */
    public class DHAgreement
    {
        private DHPrivateKeyParameters _key;
        private DHParameters _dhParams;
        private IBigInteger _privateValue;
        private ISecureRandom _random;

        public void Init(ICipherParameters parameters)
        {
            IAsymmetricKeyParameter kParam;
            var rParam = parameters as ParametersWithRandom;
            if (rParam != null)
            {
                _random = rParam.Random;
                kParam = (AsymmetricKeyParameter)rParam.Parameters;
            }
            else
            {
                _random = new SecureRandom();
                kParam = (AsymmetricKeyParameter)parameters;
            }

            if (!(kParam is DHPrivateKeyParameters))
            {
                throw new ArgumentException("DHEngine expects DHPrivateKeyParameters");
            }

            _key = (DHPrivateKeyParameters)kParam;
            _dhParams = _key.Parameters;
        }

        /**
         * calculate our initial message.
         */
        public IBigInteger CalculateMessage()
        {
            var dhGen = new DHKeyPairGenerator();
            dhGen.Init(new DHKeyGenerationParameters(_random, _dhParams));

            var dhPair = dhGen.GenerateKeyPair();
            _privateValue = ((DHPrivateKeyParameters)dhPair.Private).X;

            return ((DHPublicKeyParameters)dhPair.Public).Y;
        }

        /**
         * given a message from a given party and the corresponding public key
         * calculate the next message in the agreement sequence. In this case
         * this will represent the shared secret.
         */
        public IBigInteger CalculateAgreement(DHPublicKeyParameters pub, IBigInteger message)
        {
            if (pub == null)
                throw new ArgumentNullException("pub");
            if (message == null)
                throw new ArgumentNullException("message");

            if (!pub.Parameters.Equals(_dhParams))
            {
                throw new ArgumentException("Diffie-Hellman public key has wrong parameters.");
            }

            var p = _dhParams.P;
            return message.ModPow(_key.X, p).Multiply(pub.Y.ModPow(_privateValue, p)).Mod(p);
        }
    }
}

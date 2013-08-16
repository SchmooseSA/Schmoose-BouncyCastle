using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers
{
    /**
     * The Digital Signature Algorithm - as described in "Handbook of Applied
     * Cryptography", pages 452 - 453.
     */
    public class DsaSigner : IDsa
    {
        private DsaKeyParameters _key;
        private ISecureRandom _random;

        public string AlgorithmName
        {
            get { return "DSA"; }
        }

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            if (forSigning)
            {
                if (parameters is ParametersWithRandom)
                {
                    var rParam = (ParametersWithRandom)parameters;

                    _random = rParam.Random;
                    parameters = rParam.Parameters;
                }
                else
                {
                    _random = new SecureRandom();
                }

                if (!(parameters is DsaPrivateKeyParameters))
                    throw new InvalidKeyException("DSA private key required for signing");

                _key = (DsaPrivateKeyParameters)parameters;
            }
            else
            {
                if (!(parameters is DsaPublicKeyParameters))
                    throw new InvalidKeyException("DSA public key required for verification");

                _key = (DsaPublicKeyParameters)parameters;
            }
        }

        /**
         * Generate a signature for the given message using the key we were
         * initialised with. For conventional DSA the message should be a SHA-1
         * hash of the message of interest.
         *
         * @param message the message that will be verified later.
         */
        public IBigInteger[] GenerateSignature(byte[] message)
        {
            var parameters = _key.Parameters;
            var q = parameters.Q;
            var m = CalculateE(q, message);
            IBigInteger k;
            do
            {
                k = new BigInteger(q.BitLength, _random);
            }
            while (k.CompareTo(q) >= 0);

            var r = parameters.G.ModPow(k, parameters.P).Mod(q);
            k = k.ModInverse(q).Multiply(m.Add(((DsaPrivateKeyParameters)_key).X.Multiply(r)));

            var s = k.Mod(q);

            return new[] { r, s };
        }

        /**
         * return true if the value r and s represent a DSA signature for
         * the passed in message for standard DSA the message should be a
         * SHA-1 hash of the real message to be verified.
         */
        public bool VerifySignature(byte[] message, IBigInteger r, IBigInteger s)
        {
            var parameters = _key.Parameters;
            var q = parameters.Q;
            var m = CalculateE(q, message);

            if (r.SignValue <= 0 || q.CompareTo(r) <= 0)
            {
                return false;
            }

            if (s.SignValue <= 0 || q.CompareTo(s) <= 0)
            {
                return false;
            }

            var w = s.ModInverse(q);

            var u1 = m.Multiply(w).Mod(q);
            var u2 = r.Multiply(w).Mod(q);

            var p = parameters.P;
            u1 = parameters.G.ModPow(u1, p);
            u2 = ((DsaPublicKeyParameters)_key).Y.ModPow(u2, p);

            var v = u1.Multiply(u2).Mod(p).Mod(q);

            return v.Equals(r);
        }

        private static IBigInteger CalculateE(IBigInteger n, byte[] message)
        {
            var length = System.Math.Min(message.Length, n.BitLength / 8);
            return new BigInteger(1, message, 0, length);
        }
    }
}

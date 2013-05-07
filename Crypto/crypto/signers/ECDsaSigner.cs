using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers
{
    /**
     * EC-DSA as described in X9.62
     */
    public class ECDsaSigner : IDsa
    {
        private ECKeyParameters _key;
        private ISecureRandom _random;

        public string AlgorithmName
        {
            get { return "ECDSA"; }
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

                if (!(parameters is ECPrivateKeyParameters))
                    throw new InvalidKeyException("EC private key required for signing");

                _key = (ECPrivateKeyParameters)parameters;
            }
            else
            {
                if (!(parameters is ECPublicKeyParameters))
                    throw new InvalidKeyException("EC public key required for verification");

                _key = (ECPublicKeyParameters)parameters;
            }
        }

        // 5.3 pg 28
        /**
         * Generate a signature for the given message using the key we were
         * initialised with. For conventional DSA the message should be a SHA-1
         * hash of the message of interest.
         *
         * @param message the message that will be verified later.
         */
        public IBigInteger[] GenerateSignature(byte[] message)
        {
            var n = _key.Parameters.N;
            var e = CalculateE(n, message);

            IBigInteger r;
            IBigInteger s;

            // 5.3.2
            do // Generate s
            {
                IBigInteger k;
                
                do // Generate r
                {
                    do
                    {
                        k = new BigInteger(n.BitLength, _random);
                    }
                    while (k.SignValue == 0 || k.CompareTo(n) >= 0);

                    var p = _key.Parameters.G.Multiply(k);

                    // 5.3.3
                    var x = p.X.ToBigInteger();
                    r = x.Mod(n);
                }
                while (r.SignValue == 0);

                var d = ((ECPrivateKeyParameters)_key).D;

                s = k.ModInverse(n).Multiply(e.Add(d.Multiply(r))).Mod(n);
            }
            while (s.SignValue == 0);

            return new[] { r, s };
        }

        // 5.4 pg 29
        /**
         * return true if the value r and s represent a DSA signature for
         * the passed in message (for standard DSA the message should be
         * a SHA-1 hash of the real message to be verified).
         */
        public bool VerifySignature(byte[] message, IBigInteger r, IBigInteger s)
        {
            var n = _key.Parameters.N;

            // r and s should both in the range [1,n-1]
            if (r.SignValue < 1 || s.SignValue < 1 || r.CompareTo(n) >= 0 || s.CompareTo(n) >= 0)
            {
                return false;
            }

            var e = CalculateE(n, message);
            var c = s.ModInverse(n);

            var u1 = e.Multiply(c).Mod(n);
            var u2 = r.Multiply(c).Mod(n);

            var g = _key.Parameters.G;                       
            var q = ((ECPublicKeyParameters)_key).Q;

            var point = ECAlgorithms.SumOfTwoMultiplies(g, u1, q, u2);

            var v = point.X.ToBigInteger().Mod(n);                        
            return v.Equals(r);
        }

        private static IBigInteger CalculateE(IBigInteger n, byte[] message)
        {
            var messageBitLength = message.Length * 8;
            IBigInteger trunc = new BigInteger(1, message);

            if (n.BitLength < messageBitLength)
            {
                trunc = trunc.ShiftRight(messageBitLength - n.BitLength);
            }

            return trunc;
        }
    }
}

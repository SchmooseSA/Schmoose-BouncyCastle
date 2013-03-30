using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers
{
	/**
	 * EC-DSA as described in X9.62
	 */
	public class ECDsaSigner
		: IDsa
	{
		private ECKeyParameters key;
		private ISecureRandom random;

		public string AlgorithmName
		{
			get { return "ECDSA"; }
		}

		public void Init(
			bool				forSigning,
			ICipherParameters	parameters)
		{
			if (forSigning)
			{
				if (parameters is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom) parameters;

					this.random = rParam.Random;
					parameters = rParam.Parameters;
				}
				else
				{
					this.random = new SecureRandom();
				}

				if (!(parameters is ECPrivateKeyParameters))
					throw new InvalidKeyException("EC private key required for signing");

				this.key = (ECPrivateKeyParameters) parameters;
			}
			else
			{
				if (!(parameters is ECPublicKeyParameters))
					throw new InvalidKeyException("EC public key required for verification");

				this.key = (ECPublicKeyParameters) parameters;
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
		public IBigInteger[] GenerateSignature(
			byte[] message)
		{
            IBigInteger n = key.Parameters.N;
            IBigInteger e = calculateE(n, message);

            IBigInteger r = null;
			IBigInteger s = null;

			// 5.3.2
			do // Generate s
			{
                IBigInteger k = null;

				do // Generate r
				{
					do
					{
						k = new BigInteger(n.BitLength, random);
					}
					while (k.SignValue == 0 || k.CompareTo(n) >= 0);

					ECPoint p = key.Parameters.G.Multiply(k);

					// 5.3.3
                    IBigInteger x = p.X.ToBigInteger();

					r = x.Mod(n);
				}
				while (r.SignValue == 0);

				var d = ((ECPrivateKeyParameters)key).D;

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
		public bool VerifySignature(
			byte[]		message,
            IBigInteger r,
            IBigInteger s)
		{
			IBigInteger n = key.Parameters.N;

			// r and s should both in the range [1,n-1]
			if (r.SignValue < 1 || s.SignValue < 1
				|| r.CompareTo(n) >= 0 || s.CompareTo(n) >= 0)
			{
				return false;
			}

			var e = calculateE(n, message);
            var c = s.ModInverse(n);

            var u1 = e.Multiply(c).Mod(n);
            var u2 = r.Multiply(c).Mod(n);

			ECPoint G = key.Parameters.G;
			ECPoint Q = ((ECPublicKeyParameters) key).Q;

			ECPoint point = ECAlgorithms.SumOfTwoMultiplies(G, u1, Q, u2);

            var v = point.X.ToBigInteger().Mod(n);

			return v.Equals(r);
		}

		private IBigInteger calculateE(
            IBigInteger n,
			byte[]		message)
		{
			int messageBitLength = message.Length * 8;
            IBigInteger trunc = new BigInteger(1, message);

			if (n.BitLength < messageBitLength)
			{
				trunc = trunc.ShiftRight(messageBitLength - n.BitLength);
			}

			return trunc;
		}
	}
}

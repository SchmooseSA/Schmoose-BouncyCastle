using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
	/**
	 * GOST R 34.10-2001 Signature Algorithm
	 */
	public class ECGost3410Signer
		: IDsa
	{
		private ECKeyParameters key;
		private ISecureRandom random;

		public string AlgorithmName
		{
			get { return "ECGOST3410"; }
		}

		public void Init(
			bool				forSigning,
			ICipherParameters	parameters)
		{
			if (forSigning)
			{
				if (parameters is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)parameters;

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

				this.key = (ECPublicKeyParameters)parameters;
			}
		}

		/**
		 * generate a signature for the given message using the key we were
		 * initialised with. For conventional GOST3410 the message should be a GOST3411
		 * hash of the message of interest.
		 *
		 * @param message the message that will be verified later.
		 */
        public IBigInteger[] GenerateSignature(
			byte[] message)
		{
			byte[] mRev = new byte[message.Length]; // conversion is little-endian
			for (int i = 0; i != mRev.Length; i++)
			{
				mRev[i] = message[mRev.Length - 1 - i];
			}

            IBigInteger e = new BigInteger(1, mRev);
            IBigInteger n = key.Parameters.N;

            IBigInteger r = null;
            IBigInteger s = null;

			do // generate s
			{
                IBigInteger k = null;

				do // generate r
				{
					do
					{
						k = new BigInteger(n.BitLength, random);
					}
					while (k.SignValue == 0);

					ECPoint p = key.Parameters.G.Multiply(k);

                    IBigInteger x = p.X.ToBigInteger();

					r = x.Mod(n);
				}
				while (r.SignValue == 0);

				IBigInteger d = ((ECPrivateKeyParameters)key).D;

				s = (k.Multiply(e)).Add(d.Multiply(r)).Mod(n);
			}
			while (s.SignValue == 0);

            return new IBigInteger[] { r, s };
		}

		/**
		 * return true if the value r and s represent a GOST3410 signature for
		 * the passed in message (for standard GOST3410 the message should be
		 * a GOST3411 hash of the real message to be verified).
		 */
		public bool VerifySignature(
			byte[]		message,
            IBigInteger r,
            IBigInteger s)
		{
			byte[] mRev = new byte[message.Length]; // conversion is little-endian
			for (int i = 0; i != mRev.Length; i++)
			{
				mRev[i] = message[mRev.Length - 1 - i];
			}

            IBigInteger e = new BigInteger(1, mRev);
            IBigInteger n = key.Parameters.N;

			// r in the range [1,n-1]
			if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(n) >= 0)
			{
				return false;
			}

			// s in the range [1,n-1]
			if (s.CompareTo(BigInteger.One) < 0 || s.CompareTo(n) >= 0)
			{
				return false;
			}

            IBigInteger v = e.ModInverse(n);

            IBigInteger z1 = s.Multiply(v).Mod(n);
            IBigInteger z2 = (n.Subtract(r)).Multiply(v).Mod(n);

			ECPoint G = key.Parameters.G; // P
			ECPoint Q = ((ECPublicKeyParameters)key).Q;

			ECPoint point = ECAlgorithms.SumOfTwoMultiplies(G, z1, Q, z2);

            IBigInteger R = point.X.ToBigInteger().Mod(n);

			return R.Equals(r);
		}
	}
}

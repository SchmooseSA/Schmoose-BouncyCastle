using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers
{
	/**
	 * The Digital Signature Algorithm - as described in "Handbook of Applied
	 * Cryptography", pages 452 - 453.
	 */
	public class DsaSigner
		: IDsa
	{
		private DsaKeyParameters key;
		private ISecureRandom random;

		public string AlgorithmName
		{
			get { return "DSA"; }
		}

		public void Init(
			bool				forSigning,
			ICipherParameters	parameters)
		{
			if (forSigning)
			{
				if (parameters is ParametersWithRandom)
				{
					var rParam = (ParametersWithRandom)parameters;

					this.random = rParam.Random;
					parameters = rParam.Parameters;
				}
				else
				{
					this.random = new SecureRandom();
				}

				if (!(parameters is DsaPrivateKeyParameters))
					throw new InvalidKeyException("DSA private key required for signing");

				this.key = (DsaPrivateKeyParameters) parameters;
			}
			else
			{
				if (!(parameters is DsaPublicKeyParameters))
					throw new InvalidKeyException("DSA public key required for verification");

				this.key = (DsaPublicKeyParameters) parameters;
			}
		}

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
			var parameters = key.Parameters;
			IBigInteger q = parameters.Q;
			IBigInteger m = calculateE(q, message);
			IBigInteger k;

			do
			{
				k = new BigInteger(q.BitLength, random);
			}
			while (k.CompareTo(q) >= 0);

			var r = parameters.G.ModPow(k, parameters.P).Mod(q);

			k = k.ModInverse(q).Multiply(
				m.Add(((DsaPrivateKeyParameters)key).X.Multiply(r)));

			var s = k.Mod(q);

			return new[]{ r, s };
		}

		/**
		 * return true if the value r and s represent a DSA signature for
		 * the passed in message for standard DSA the message should be a
		 * SHA-1 hash of the real message to be verified.
		 */
		public bool VerifySignature(
			byte[]		message,
			IBigInteger	r,
			IBigInteger	s)
		{
			var parameters = key.Parameters;
			var q = parameters.Q;
			var m = calculateE(q, message);

			if (r.SignValue <= 0 || q.CompareTo(r) <= 0)
			{
				return false;
			}

			if (s.SignValue <= 0 || q.CompareTo(s) <= 0)
			{
				return false;
			}

            IBigInteger w = s.ModInverse(q);

            IBigInteger u1 = m.Multiply(w).Mod(q);
			IBigInteger u2 = r.Multiply(w).Mod(q);

            IBigInteger p = parameters.P;
			u1 = parameters.G.ModPow(u1, p);
			u2 = ((DsaPublicKeyParameters)key).Y.ModPow(u2, p);

            IBigInteger v = u1.Multiply(u2).Mod(p).Mod(q);

			return v.Equals(r);
		}

		private IBigInteger calculateE(
            IBigInteger n,
			byte[]		message)
		{
			int length = System.Math.Min(message.Length, n.BitLength / 8);

			return new BigInteger(1, message, 0, length);
		}
	}
}

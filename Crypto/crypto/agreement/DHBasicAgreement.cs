using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
	/**
	 * a Diffie-Hellman key agreement class.
	 * <p>
	 * note: This is only the basic algorithm, it doesn't take advantage of
	 * long term public keys if they are available. See the DHAgreement class
	 * for a "better" implementation.</p>
	 */
	public class DHBasicAgreement : IBasicAgreement
	{
		private DHPrivateKeyParameters	_key;
		private DHParameters			_dhParams;

		public void Init(ICipherParameters parameters)
		{
			if (parameters is ParametersWithRandom)
			{
				parameters = ((ParametersWithRandom) parameters).Parameters;
			}
			if (!(parameters is DHPrivateKeyParameters))
			{
				throw new ArgumentException("DHEngine expects DHPrivateKeyParameters");
			}

			this._key = (DHPrivateKeyParameters) parameters;
			this._dhParams = _key.Parameters;
		}

		/**
		 * given a short term public key from a given party calculate the next
		 * message in the agreement sequence.
		 */
		public IBigInteger CalculateAgreement(ICipherParameters pubKey)
		{
			if (this._key == null)
				throw new InvalidOperationException("Agreement algorithm not initialised");

			var pub = (DHPublicKeyParameters)pubKey;
			if (!pub.Parameters.Equals(_dhParams))
			{
				throw new ArgumentException("Diffie-Hellman public key has wrong parameters.");
			}

			return pub.Y.ModPow(_key.X, _dhParams.P);
		}
	}

}

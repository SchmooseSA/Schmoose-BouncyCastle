using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class RsaBlindingParameters
		: ICipherParameters
	{
		private readonly RsaKeyParameters	publicKey;
		private readonly IBigInteger			blindingFactor;

		public RsaBlindingParameters(
			RsaKeyParameters	publicKey,
			IBigInteger			blindingFactor)
		{
			if (publicKey.IsPrivate)
				throw new ArgumentException("RSA parameters should be for a public key");

			this.publicKey = publicKey;
			this.blindingFactor = blindingFactor;
		}

		public RsaKeyParameters PublicKey
		{
			get { return publicKey; }
		}

		public IBigInteger BlindingFactor
		{
			get { return blindingFactor; }
		}
	}
}

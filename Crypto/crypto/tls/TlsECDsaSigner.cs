using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Crypto.Tls
{
	internal class TlsECDsaSigner
		: TlsDsaSigner
	{
		public override bool IsValidPublicKey(IAsymmetricKeyParameter publicKey)
		{
			return publicKey is ECPublicKeyParameters;
		}

		protected override IDsa CreateDsaImpl()
		{
			return new ECDsaSigner();
		}
	}
}

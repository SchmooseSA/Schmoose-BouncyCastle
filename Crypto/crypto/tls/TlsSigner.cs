using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
	public interface TlsSigner
	{
    	byte[] CalculateRawSignature(SecureRandom random, IAsymmetricKeyParameter privateKey,
			byte[] md5andsha1);
		bool VerifyRawSignature(byte[] sigBytes, IAsymmetricKeyParameter publicKey, byte[] md5andsha1);

		ISigner CreateSigner(SecureRandom random, IAsymmetricKeyParameter privateKey);
		ISigner CreateVerifyer(IAsymmetricKeyParameter publicKey);

		bool IsValidPublicKey(IAsymmetricKeyParameter publicKey);
	}
}

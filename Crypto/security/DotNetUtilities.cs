#if !(NETCF_1_0)

using System;
#if NETFX_CORE
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
#else
using System.Security.Cryptography;
using SystemX509 = System.Security.Cryptography.X509Certificates;
#endif

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Security
{
    /// <summary>
    /// A class containing methods to interface the BouncyCastle world to the .NET Crypto world.
    /// </summary>
    public static class DotNetUtilities
    {
#if !NETFX_CORE
	    /// <summary>
		/// Create an System.Security.Cryptography.X509Certificate from an X509Certificate Structure.
		/// </summary>
		/// <param name="x509Struct"></param>
		/// <returns>A System.Security.Cryptography.X509Certificate.</returns>
		public static SystemX509.X509Certificate ToX509Certificate(
			X509CertificateStructure x509Struct)
		{
			return new SystemX509.X509Certificate(x509Struct.GetDerEncoded());
		}

		public static SystemX509.X509Certificate ToX509Certificate(
			X509Certificate x509Cert)
		{
			return new SystemX509.X509Certificate(x509Cert.GetEncoded());
		}

		public static X509Certificate FromX509Certificate(
			SystemX509.X509Certificate x509Cert)
		{
			return new X509CertificateParser().ReadCertificate(x509Cert.GetRawCertData());
		}
#endif
#if !(SILVERLIGHT || NETFX_CORE)
		public static AsymmetricCipherKeyPair GetDsaKeyPair(
			DSA dsa)
		{
			return GetDsaKeyPair(dsa.ExportParameters(true));
		}

		public static AsymmetricCipherKeyPair GetDsaKeyPair(
			DSAParameters dp)
		{
			DsaValidationParameters validationParameters = (dp.Seed != null)
				?	new DsaValidationParameters(dp.Seed, dp.Counter)
				:	null;

			DsaParameters parameters = new DsaParameters(
				new BigInteger(1, dp.P),
				new BigInteger(1, dp.Q),
				new BigInteger(1, dp.G),
				validationParameters);

			DsaPublicKeyParameters pubKey = new DsaPublicKeyParameters(
				new BigInteger(1, dp.Y),
				parameters);

			DsaPrivateKeyParameters privKey = new DsaPrivateKeyParameters(
				new BigInteger(1, dp.X),
				parameters);

			return new AsymmetricCipherKeyPair(pubKey, privKey);
		}

		public static DsaPublicKeyParameters GetDsaPublicKey(
			DSA dsa)
		{
			return GetDsaPublicKey(dsa.ExportParameters(false));
		}

		public static DsaPublicKeyParameters GetDsaPublicKey(
			DSAParameters dp)
		{
			DsaValidationParameters validationParameters = (dp.Seed != null)
				?	new DsaValidationParameters(dp.Seed, dp.Counter)
				:	null;

			DsaParameters parameters = new DsaParameters(
				new BigInteger(1, dp.P),
				new BigInteger(1, dp.Q),
				new BigInteger(1, dp.G),
				validationParameters);

			return new DsaPublicKeyParameters(
				new BigInteger(1, dp.Y),
				parameters);
		}
#endif

#if NETFX_CORE
        public static AsymmetricCipherKeyPair GetRsaKeyPair(CryptographicKey key)
        {
            var privateKeyBuffer = key.Export(CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);
            
            byte[] privateKeyBytes;
            CryptographicBuffer.CopyToByteArray(privateKeyBuffer, out privateKeyBytes);
            
            var asn1 = (Asn1Sequence) Asn1Object.FromByteArray(privateKeyBytes);
            var rsa = new RsaPrivateKeyStructure(asn1);

            var pubKey = new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent);
            var privKey = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent,
                rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2,
                rsa.Coefficient);

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
#elif !SILVERLIGHT4

		public static AsymmetricCipherKeyPair GetRsaKeyPair(
			RSA rsa)
		{
			return GetRsaKeyPair(rsa.ExportParameters(true));
		}

		public static AsymmetricCipherKeyPair GetRsaKeyPair(
			RSAParameters rp)
		{
			IBigInteger modulus = new BigInteger(1, rp.Modulus);
			IBigInteger pubExp = new BigInteger(1, rp.Exponent);

			RsaKeyParameters pubKey = new RsaKeyParameters(
				false,
				modulus,
				pubExp);

			RsaPrivateCrtKeyParameters privKey = new RsaPrivateCrtKeyParameters(
				modulus,
				pubExp,
				new BigInteger(1, rp.D),
				new BigInteger(1, rp.P),
				new BigInteger(1, rp.Q),
				new BigInteger(1, rp.DP),
				new BigInteger(1, rp.DQ),
				new BigInteger(1, rp.InverseQ));

			return new AsymmetricCipherKeyPair(pubKey, privKey);
		}

		public static RsaKeyParameters GetRsaPublicKey(
			RSA rsa)
		{
			return GetRsaPublicKey(rsa.ExportParameters(false));
		}

		public static RsaKeyParameters GetRsaPublicKey(
			RSAParameters rp)
		{
			return new RsaKeyParameters(
				false,
				new BigInteger(1, rp.Modulus),
				new BigInteger(1, rp.Exponent));
		}

		public static AsymmetricCipherKeyPair GetKeyPair(AsymmetricAlgorithm privateKey)
		{
#if !SILVERLIGHT
			if (privateKey is DSA)
			{
				return GetDsaKeyPair((DSA)privateKey);
			}
#endif

			if (privateKey is RSA)
			{
				return GetRsaKeyPair((RSA)privateKey);
			}

			throw new ArgumentException("Unsupported algorithm specified", "privateKey");
		}

		public static RSA ToRSA(RsaKeyParameters rsaKey)
		{
			RSAParameters rp = ToRSAParameters(rsaKey);
			RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
			rsaCsp.ImportParameters(rp);
			return rsaCsp;
		}

		public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey)
		{
			RSAParameters rp = ToRSAParameters(privKey);
			RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
			rsaCsp.ImportParameters(rp);
			return rsaCsp;
		}

		public static RSAParameters ToRSAParameters(RsaKeyParameters rsaKey)
		{
			RSAParameters rp = new RSAParameters();
			rp.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();
			if (rsaKey.IsPrivate)
				rp.D = rsaKey.Exponent.ToByteArrayUnsigned();
			else
				rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
			return rp;
		}

		public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
		{
			RSAParameters rp = new RSAParameters();
			rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
			rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
			rp.D = privKey.Exponent.ToByteArrayUnsigned();
			rp.P = privKey.P.ToByteArrayUnsigned();
			rp.Q = privKey.Q.ToByteArrayUnsigned();
			rp.DP = privKey.DP.ToByteArrayUnsigned();
			rp.DQ = privKey.DQ.ToByteArrayUnsigned();
			rp.InverseQ = privKey.QInv.ToByteArrayUnsigned();
			return rp;
		}
#endif
    }

}

#endif

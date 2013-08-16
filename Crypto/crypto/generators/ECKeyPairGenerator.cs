using System;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    public class ECKeyPairGenerator : IAsymmetricCipherKeyPairGenerator
    {
		private readonly string _algorithm;

		private ECDomainParameters _parameters;
		private DerObjectIdentifier _publicKeyParamSet;
        private ISecureRandom _random;
        private HashAlgorithmTag _hashAlgorithm;
        private SymmetricKeyAlgorithmTag _symmetricKeyAlgorithm;

		public ECKeyPairGenerator()
			: this("EC")
		{
		}

		public ECKeyPairGenerator(string algorithm)
		{
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");

			_algorithm = VerifyAlgorithmName(algorithm);
		}

		public void Init(IKeyGenerationParameters parameters)
        {
		    var ecKeyGenerationParameters = parameters as ECKeyGenerationParameters;
		    if (ecKeyGenerationParameters != null)
			{
				_publicKeyParamSet = ecKeyGenerationParameters.PublicKeyParamSet;
                _parameters = ecKeyGenerationParameters.DomainParameters;
			    _hashAlgorithm = ecKeyGenerationParameters.HashAlgorithm;
			    _symmetricKeyAlgorithm = ecKeyGenerationParameters.SymmetricKeyAlgorithm;
			}
			else
			{
				DerObjectIdentifier oid;
				switch (parameters.Strength)
				{
					case 192:
						oid = X9ObjectIdentifiers.Prime192v1;
						break;
					case 224:
						oid = SecObjectIdentifiers.SecP224r1;
						break;
					case 239:
						oid = X9ObjectIdentifiers.Prime239v1;
						break;
					case 256:
						oid = X9ObjectIdentifiers.Prime256v1;
						break;
					case 384:
						oid = SecObjectIdentifiers.SecP384r1;
						break;
					case 521:
						oid = SecObjectIdentifiers.SecP521r1;
						break;
					default:
						throw new InvalidParameterException("unknown key size.");
				}

				var ecps = FindECCurveByOid(oid);
				_parameters = new ECDomainParameters(ecps.Curve, ecps.G, ecps.N, ecps.H, ecps.GetSeed());
                _hashAlgorithm = HashAlgorithmTag.Sha512;
                _symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256;
			}

			_random = parameters.Random;
		}

		/**
         * Given the domain parameters this routine Generates an EC key
         * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
         */
        public IAsymmetricCipherKeyPair GenerateKeyPair()
        {
            var n = _parameters.N;
            IBigInteger d;
            do
            {
                d = new BigInteger(n.BitLength, _random);
            }
            while (d.SignValue == 0 || (d.CompareTo(n) >= 0));

            var isEcdh = _algorithm == "ECDH";

            var q = _parameters.G.Multiply(d);

            if (_publicKeyParamSet != null)
			{
			    return new AsymmetricCipherKeyPair(
                    isEcdh 
                        ? new ECDHPublicKeyParameters(q, _publicKeyParamSet, _hashAlgorithm, _symmetricKeyAlgorithm) 
                        : new ECPublicKeyParameters(_algorithm, q, _publicKeyParamSet), 
                    new ECPrivateKeyParameters(_algorithm, d, _publicKeyParamSet));
			}
            return new AsymmetricCipherKeyPair(
				isEcdh
				    ? new ECDHPublicKeyParameters(q, _parameters, _hashAlgorithm, _symmetricKeyAlgorithm)
				    : new ECPublicKeyParameters(_algorithm, q, _parameters),
				new ECPrivateKeyParameters(_algorithm, d, _parameters));
		}

		private static string VerifyAlgorithmName(string algorithm)
		{
		    var upper = Platform.StringToUpper(algorithm);
			switch (upper)
			{
				case "EC":
				case "ECDSA":
				case "ECDH":
				case "ECDHC":
				case "ECGOST3410":
				case "ECMQV":
					break;
				default:
					throw new ArgumentException("unrecognised algorithm: " + algorithm, "algorithm");
			}

			return upper;
		}

		internal static X9ECParameters FindECCurveByOid(DerObjectIdentifier oid)
		{
			// TODO ECGost3410NamedCurves support (returns ECDomainParameters though)

		    return X962NamedCurves.GetByOid(oid) ??
		           (SecNamedCurves.GetByOid(oid) ?? 
                   (NistNamedCurves.GetByOid(oid) ?? TeleTrusTNamedCurves.GetByOid(oid)));
		}

		internal static ECPublicKeyParameters GetCorrespondingPublicKey(ECPrivateKeyParameters privKey)
		{
			var parameters = privKey.Parameters;
			var q = parameters.G.Multiply(privKey.D);

			return privKey.PublicKeyParamSet != null 
                ? new ECPublicKeyParameters(privKey.AlgorithmName, q, privKey.PublicKeyParamSet) 
                : new ECPublicKeyParameters(privKey.AlgorithmName, q, parameters);
		}
	}
}

using System;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public abstract class ECKeyParameters : AsymmetricKeyParameter
    {
        private readonly string _algorithm;
        private readonly ECDomainParameters _parameters;
        private readonly DerObjectIdentifier _publicKeyParamSet;

        protected ECKeyParameters(string algorithm, bool isPrivate, ECDomainParameters parameters)
            : base(isPrivate)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (parameters == null)
                throw new ArgumentNullException("parameters");

            _algorithm = VerifyAlgorithmName(algorithm);
            _parameters = parameters;
        }

        protected ECKeyParameters(string algorithm, bool isPrivate, DerObjectIdentifier publicKeyParamSet)
            : base(isPrivate)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (publicKeyParamSet == null)
                throw new ArgumentNullException("publicKeyParamSet");

            _algorithm = VerifyAlgorithmName(algorithm);
            _parameters = LookupParameters(publicKeyParamSet);
            _publicKeyParamSet = publicKeyParamSet;
        }

        public string AlgorithmName
        {
            get { return _algorithm; }
        }

        public ECDomainParameters Parameters
        {
            get { return _parameters; }
        }

        public DerObjectIdentifier PublicKeyParamSet
        {
            get { return _publicKeyParamSet; }
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECDomainParameters;

            return other != null && Equals(other);
        }

        protected bool Equals(ECKeyParameters other)
        {
            return _parameters.Equals(other.Parameters) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return _parameters.GetHashCode() ^ base.GetHashCode();
        }

        internal ECKeyGenerationParameters CreateKeyGenerationParameters(SecureRandom random)
        {
            return _publicKeyParamSet != null 
                ? new ECKeyGenerationParameters(_publicKeyParamSet, random) 
                : new ECKeyGenerationParameters(_parameters, random);
        }

        private static string VerifyAlgorithmName(string algorithm)
        {
            var upper = algorithm.ToUpper(CultureInfo.InvariantCulture);

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

        internal static ECDomainParameters LookupParameters(DerObjectIdentifier publicKeyParamSet)
        {
            if (publicKeyParamSet == null)
                throw new ArgumentNullException("publicKeyParamSet");

            var p = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
            if (p == null)
            {
                var x9 = ECKeyPairGenerator.FindECCurveByOid(publicKeyParamSet);
                if (x9 == null)
                {
                    throw new ArgumentException("OID is not a valid public key parameter set", "publicKeyParamSet");
                }

                p = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());
            }

            return p;
        }
    }
}

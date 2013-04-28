using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECPrivateKeyParameters : ECKeyParameters
    {
        private readonly IBigInteger _d;

        public ECPrivateKeyParameters(IBigInteger d, ECDomainParameters parameters)
            : this("EC", d, parameters)
        {
        }

        [Obsolete("Use version with explicit 'algorithm' parameter")]
        public ECPrivateKeyParameters(IBigInteger d, DerObjectIdentifier publicKeyParamSet)
            : base("ECGOST3410", true, publicKeyParamSet)
        {
            if (d == null)
                throw new ArgumentNullException("d");

            _d = d;
        }

        public ECPrivateKeyParameters(string algorithm, IBigInteger d, ECDomainParameters parameters)
            : base(algorithm, true, parameters)
        {
            if (d == null)
                throw new ArgumentNullException("d");

            _d = d;
        }

        public ECPrivateKeyParameters(string algorithm, IBigInteger d, DerObjectIdentifier publicKeyParamSet)
            : base(algorithm, true, publicKeyParamSet)
        {
            if (d == null)
                throw new ArgumentNullException("d");

            _d = d;
        }

        public IBigInteger D
        {
            get { return _d; }
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECPrivateKeyParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(ECPrivateKeyParameters other)
        {
            return _d.Equals(other.D) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return _d.GetHashCode() ^ base.GetHashCode();
        }
    }
}

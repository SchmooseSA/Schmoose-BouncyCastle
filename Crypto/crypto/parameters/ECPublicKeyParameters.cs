using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECPublicKeyParameters : ECKeyParameters
    {
        private readonly ECPoint _q;

        public ECPublicKeyParameters(ECPoint q, ECDomainParameters parameters)
            : this("EC", q, parameters)
        {
        }

        [Obsolete("Use version with explicit 'algorithm' parameter")]
        public ECPublicKeyParameters(ECPoint q, DerObjectIdentifier publicKeyParamSet)
            : base("ECGOST3410", false, publicKeyParamSet)
        {
            if (q == null)
                throw new ArgumentNullException("q");

            _q = q;
        }

        public ECPublicKeyParameters(string algorithm, ECPoint q, ECDomainParameters parameters)
            : base(algorithm, false, parameters)
        {
            if (q == null)
                throw new ArgumentNullException("q");

            _q = q;
        }

        public ECPublicKeyParameters(string algorithm, ECPoint q, DerObjectIdentifier publicKeyParamSet)
            : base(algorithm, false, publicKeyParamSet)
        {
            if (q == null)
                throw new ArgumentNullException("q");

            _q = q;
        }

        public ECPoint Q
        {
            get { return _q; }
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECPublicKeyParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(ECPublicKeyParameters other)
        {
            return _q.Equals(other._q) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return _q.GetHashCode() ^ base.GetHashCode();
        }
    }
}

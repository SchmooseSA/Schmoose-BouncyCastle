using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ElGamalPublicKeyParameters : ElGamalKeyParameters
    {
        private readonly IBigInteger _y;

        public ElGamalPublicKeyParameters(IBigInteger y, ElGamalParameters parameters)
            : base(false, parameters)
        {
            if (y == null)
                throw new ArgumentNullException("y");

            _y = y;
        }

        public IBigInteger Y
        {
            get { return _y; }
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ElGamalPublicKeyParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(ElGamalPublicKeyParameters other)
        {
            return _y.Equals(other.Y) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return _y.GetHashCode() ^ base.GetHashCode();
        }
    }
}

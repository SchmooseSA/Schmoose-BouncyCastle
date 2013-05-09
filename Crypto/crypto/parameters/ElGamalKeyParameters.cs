using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ElGamalKeyParameters : AsymmetricKeyParameter
    {
        private readonly ElGamalParameters _parameters;

        protected ElGamalKeyParameters(bool isPrivate, ElGamalParameters parameters)
            : base(isPrivate)
        {
            // TODO Should we allow 'parameters' to be null?
            _parameters = parameters;
        }

        public ElGamalParameters Parameters
        {
            get { return _parameters; }
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ElGamalKeyParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(ElGamalKeyParameters other)
        {
            return Object.Equals(_parameters, other.Parameters)
                && base.Equals(other);
        }

        public override int GetHashCode()
        {
            var hc = base.GetHashCode();

            if (_parameters != null)
            {
                hc ^= _parameters.GetHashCode();
            }

            return hc;
        }
    }
}

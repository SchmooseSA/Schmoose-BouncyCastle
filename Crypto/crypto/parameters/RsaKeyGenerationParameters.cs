using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class RsaKeyGenerationParameters : KeyGenerationParameters
    {
        private readonly IBigInteger _publicExponent;
        private readonly int _certainty;

        public RsaKeyGenerationParameters(IBigInteger publicExponent, ISecureRandom random, int strength, int certainty)
            : base(random, strength)
        {
            _publicExponent = publicExponent;
            _certainty = certainty;
        }

        public IBigInteger PublicExponent
        {
            get { return _publicExponent; }
        }

        public int Certainty
        {
            get { return _certainty; }
        }

        public override bool Equals(object obj)
        {
            var other = obj as RsaKeyGenerationParameters;
            if (other == null)
                return false;
            return _certainty == other._certainty
                && _publicExponent.Equals(other._publicExponent);
        }

        public override int GetHashCode()
        {
            return _certainty.GetHashCode() ^ _publicExponent.GetHashCode();
        }
    }
}

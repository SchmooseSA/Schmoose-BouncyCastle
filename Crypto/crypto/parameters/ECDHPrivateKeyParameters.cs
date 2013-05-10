using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECDHPrivateKeyParameters : ECPrivateKeyParameters
    {
        public ECDHPrivateKeyParameters(IBigInteger d, ECDomainParameters parameters, ECDHPublicKeyParameters publicKeyParameters, byte[] fingerPrint)
            : base("ECDH", d, parameters)
        {
            this.PublicKeyParameters = publicKeyParameters;
            this.FingerPrint = (byte[])fingerPrint.Clone();
        }

        public ECDHPrivateKeyParameters(IBigInteger d, ECDHPublicKeyParameters publicKeyParameters, byte[] fingerPrint)
            : base("ECDH", d, publicKeyParameters.PublicKeyParamSet)
        {
            this.PublicKeyParameters = publicKeyParameters;
            this.FingerPrint = (byte[])fingerPrint.Clone();
        }

        /// <summary>
        /// Gets the fingerprint of the key.
        /// </summary>
        /// <value>
        /// The fingerprint of the key.
        /// </value>
        public byte[] FingerPrint { get; private set; }

        public ECDHPublicKeyParameters PublicKeyParameters { get; private set; }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECDHPrivateKeyParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(ECDHPrivateKeyParameters other)
        {
            return this.PublicKeyParameters.Equals(other.PublicKeyParameters)
                && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return this.PublicKeyParameters.GetHashCode() 
                ^ base.GetHashCode();
        }
    }
}

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECDHPublicKeyParameters : ECPublicKeyParameters
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ECDHPublicKeyParameters" /> class.
        /// </summary>
        /// <param name="q">The q.</param>
        /// <param name="parameters">The parameters.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="symmetricKeyAlgorithm">The symmetric key algorithm.</param>
        public ECDHPublicKeyParameters(ECPoint q, ECDomainParameters parameters, HashAlgorithmTag hashAlgorithm,
                                       SymmetricKeyAlgorithmTag symmetricKeyAlgorithm)
            : base("ECDH", q, parameters)
        {
            this.HashAlgorithm = hashAlgorithm;
            this.SymmetricKeyAlgorithm = symmetricKeyAlgorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ECDHPublicKeyParameters" /> class.
        /// </summary>
        /// <param name="q">The q.</param>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="symmetricKeyAlgorithm">The symmetric key algorithm.</param>
        public ECDHPublicKeyParameters(ECPoint q, DerObjectIdentifier publicKeyParamSet, HashAlgorithmTag hashAlgorithm,
                                       SymmetricKeyAlgorithmTag symmetricKeyAlgorithm)
            : base("ECDH", q, publicKeyParamSet)
        {
            this.HashAlgorithm = hashAlgorithm;
            this.SymmetricKeyAlgorithm = symmetricKeyAlgorithm;
        }

        /// <summary>
        /// Gets the hash algorithm.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithmTag HashAlgorithm { get; private set; }

        /// <summary>
        /// Gets the symmetric key algorithm.
        /// </summary>
        /// <value>
        /// The symmetric key algorithm.
        /// </value>
        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; private set; }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as ECDHPublicKeyParameters;
            return other != null && this.Equals(other);
        }

        protected bool Equals(ECDHPublicKeyParameters other)
        {
            return this.HashAlgorithm == other.HashAlgorithm 
                && this.SymmetricKeyAlgorithm == other.SymmetricKeyAlgorithm 
                && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return this.AlgorithmName.GetHashCode() 
                ^ this.SymmetricKeyAlgorithm.GetHashCode() 
                ^ base.GetHashCode();
        }
    }
}

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECKeyGenerationParameters : KeyGenerationParameters
    {
        private readonly ECDomainParameters _domainParams;
        private readonly DerObjectIdentifier _publicKeyParamSet;
        private readonly HashAlgorithmTag _hashAlgorithm;
        private readonly SymmetricKeyAlgorithmTag _symmetricKeyAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECKeyGenerationParameters"/> class.
        /// </summary>
        /// <param name="domainParameters">The domain parameters.</param>
        /// <param name="random">The random.</param>
        public ECKeyGenerationParameters(ECDomainParameters domainParameters, ISecureRandom random)
            : this(domainParameters, random, HashAlgorithmTag.Sha512, SymmetricKeyAlgorithmTag.Aes256)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ECKeyGenerationParameters"/> class.
        /// </summary>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        /// <param name="random">The random.</param>
        public ECKeyGenerationParameters(DerObjectIdentifier publicKeyParamSet, ISecureRandom random)
            : this(publicKeyParamSet, random, HashAlgorithmTag.Sha512, SymmetricKeyAlgorithmTag.Aes256) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ECKeyGenerationParameters"/> class.
        /// </summary>
        /// <param name="domainParameters">The domain parameters.</param>
        /// <param name="random">The random.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="symmetricKeyAlgorithm">The symmetric key algorithm.</param>
        public ECKeyGenerationParameters(ECDomainParameters domainParameters, ISecureRandom random, HashAlgorithmTag hashAlgorithm, SymmetricKeyAlgorithmTag symmetricKeyAlgorithm)
            : base(random, domainParameters.N.BitLength)
        {
            _domainParams = domainParameters;
            _hashAlgorithm = hashAlgorithm;
            _symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ECKeyGenerationParameters"/> class.
        /// </summary>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        /// <param name="random">The random.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="symmetricKeyAlgorithm">The symmetric key algorithm.</param>
        public ECKeyGenerationParameters(DerObjectIdentifier publicKeyParamSet, ISecureRandom random, HashAlgorithmTag hashAlgorithm, SymmetricKeyAlgorithmTag symmetricKeyAlgorithm)
            : this(ECKeyParameters.LookupParameters(publicKeyParamSet), random)
        {
            _publicKeyParamSet = publicKeyParamSet;
            _hashAlgorithm = hashAlgorithm;
            _symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        }

        /// <summary>
        /// Gets the domain parameters.
        /// </summary>
        /// <value>
        /// The domain parameters.
        /// </value>
        public ECDomainParameters DomainParameters
        {
            get { return _domainParams; }
        }

        /// <summary>
        /// Gets the hash algorithm.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return _hashAlgorithm; }
        }

        /// <summary>
        /// Gets the public key param set.
        /// </summary>
        /// <value>
        /// The public key param set.
        /// </value>
        public DerObjectIdentifier PublicKeyParamSet
        {
            get { return _publicKeyParamSet; }
        }

        /// <summary>
        /// Gets the symmetric key algorithm.
        /// </summary>
        /// <value>
        /// The symmetric key algorithm.
        /// </value>
        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm
        {
            get { return _symmetricKeyAlgorithm; }
        }
    }
}

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    public class EcdhPublicBcpgKey : EcPublicBcpgKey
    {
        private readonly byte _reserved;
        private readonly byte _hashFunctionId; 
        private readonly byte _symAlgorithmId;        

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">kdf parameter size of 3 expected.</exception>        
        public EcdhPublicBcpgKey(BcpgInputStream bcpgIn)
            : this(bcpgIn, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">kdf parameter size of 3 expected.</exception>
        /// <param name="oid">The OID.</param>
        private EcdhPublicBcpgKey(BcpgInputStream bcpgIn, DerObjectIdentifier oid)
            : base(bcpgIn, oid)
        {
            var kdfParamters = this.ReadBytesOfEncodedLength(bcpgIn);
            if(kdfParamters.Length != 3)
                throw new PgpException("kdf parameter size of 3 expected.");

            _reserved = kdfParamters[0];
            _hashFunctionId = kdfParamters[1];
            _symAlgorithmId = kdfParamters[2];

            this.VerifyHashAlgorithm();
            this.VerifySymmetricKeyAlgorithm();
        }
        
        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="point">The point.</param>
        /// <param name="oid">The oid.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="symmetricKeyAlgorithm">The symmetric key algorithm.</param>
        public EcdhPublicBcpgKey(ECPoint point, DerObjectIdentifier oid, HashAlgorithmTag hashAlgorithm,
                                 SymmetricKeyAlgorithmTag symmetricKeyAlgorithm)
            : base(point, oid)
        {
            _reserved = 1;
            _hashFunctionId = (byte)hashAlgorithm;
            _symAlgorithmId = (byte)symmetricKeyAlgorithm;

            this.VerifyHashAlgorithm();
            this.VerifySymmetricKeyAlgorithm();
        }
        
        public byte Reserved
        {
            get { return _reserved; }
        }

        /// <summary>
        /// Gets the hash algorithm.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return (HashAlgorithmTag)_hashFunctionId; }
        }

        /// <summary>
        /// Gets the symmetric key algorithm.
        /// </summary>
        /// <value>
        /// The symmetric key algorithm.
        /// </value>
        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm
        {
            get { return (SymmetricKeyAlgorithmTag)_symAlgorithmId; }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            base.Encode(bcpgOut);
            bcpgOut.WriteByte(0x3);
            bcpgOut.WriteByte(this.Reserved);
            bcpgOut.WriteByte((byte)this.HashAlgorithm);
            bcpgOut.WriteByte((byte)this.SymmetricKeyAlgorithm);
        }

        /// <summary>
        /// Verifies the hash algorithm.
        /// </summary>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">Hash algorithm must be SHA-256 or stronger.</exception>
        private void VerifyHashAlgorithm()
        {
            switch (this.HashAlgorithm)
            {
                case HashAlgorithmTag.Sha256:
                case HashAlgorithmTag.Sha384:
                case HashAlgorithmTag.Sha512:
                    break;

                default:
                    throw new PgpException("Hash algorithm must be SHA-256 or stronger.");
            }
        }

        /// <summary>
        /// Verifies the symmetric key algorithm.
        /// </summary>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">Symmetric key algorithm must be AES-128 or stronger.</exception>
        private void VerifySymmetricKeyAlgorithm()
        {
            switch (this.SymmetricKeyAlgorithm)
            {
                case SymmetricKeyAlgorithmTag.Aes128:
                case SymmetricKeyAlgorithmTag.Aes192:
                case SymmetricKeyAlgorithmTag.Aes256:
                    break;

                default:
                    throw new PgpException("Symmetric key algorithm must be AES-128 or stronger.");
            }
        }
    }
}
using System;
using System.IO;
using Org.BouncyCastle.Asn1;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A PGP signature object.</remarks>
    public class PgpSignature : IPgpSignature
    {
        public const int BinaryDocument = 0x00;
        public const int CanonicalTextDocument = 0x01;
        public const int StandAlone = 0x02;

        public const int DefaultCertification = 0x10;
        public const int NoCertification = 0x11;
        public const int CasualCertification = 0x12;
        public const int PositiveCertification = 0x13;

        public const int SubkeyBinding = 0x18;
        public const int PrimaryKeyBinding = 0x19;
        public const int DirectKey = 0x1f;
        public const int KeyRevocation = 0x20;
        public const int SubkeyRevocation = 0x28;
        public const int CertificationRevocation = 0x30;
        public const int Timestamp = 0x40;

        private readonly SignaturePacket _sigPck;
        private readonly int _signatureType;
        private readonly ITrustPacket _trustPck;

        private ISigner _sig;
        private byte _lastb; // Initial value anything but '\r'

        /// <summary>
        /// Initializes a new instance of the <see cref="PgpSignature"/> class.
        /// </summary>
        /// <param name="bcpgInput">The BCPG input.</param>
        internal PgpSignature(BcpgInputStream bcpgInput)
            : this((SignaturePacket)bcpgInput.ReadPacket())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PgpSignature"/> class.
        /// </summary>
        /// <param name="sigPacket">The sig packet.</param>
        internal PgpSignature(SignaturePacket sigPacket)
            : this(sigPacket, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PgpSignature"/> class.
        /// </summary>
        /// <param name="sigPacket">The sig packet.</param>
        /// <param name="trustPacket">The trust packet.</param>
        /// <exception cref="System.ArgumentNullException">sigPacket</exception>
        internal PgpSignature(SignaturePacket sigPacket, ITrustPacket trustPacket)
        {
            if (sigPacket == null)
                throw new ArgumentNullException("sigPacket");

            _sigPck = sigPacket;
            _signatureType = _sigPck.SignatureType;
            _trustPck = trustPacket;
        }

        /// <summary>
        /// The OpenPGP version number for this signature.
        /// </summary>
        /// <value>
        /// The version.
        /// </value>
        public int Version
        {
            get { return _sigPck.Version; }
        }

        /// <summary>
        /// The key algorithm associated with this signature.
        /// </summary>
        /// <value>
        /// The key algorithm.
        /// </value>
        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return _sigPck.KeyAlgorithm; }
        }

        /// <summary>
        /// The hash algorithm associated with this signature.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return _sigPck.HashAlgorithm; }
        }

        /// <summary>
        /// Inits the verification process.
        /// </summary>
        /// <param name="pubKey">The pub key.</param>
        /// <exception cref="PgpException">invalid key.</exception>
        public void InitVerify(IPgpPublicKey pubKey)
        {
            _lastb = 0;
            if (_sig == null)
            {
                _sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(_sigPck.KeyAlgorithm, _sigPck.HashAlgorithm));
            }
            try
            {
                _sig.Init(false, pubKey.GetKey());
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }
        }

        /// <summary>
        /// Updates the instance with the given data.
        /// </summary>
        /// <param name="b">The b.</param>
        public void Update(byte b)
        {
            if (_signatureType == CanonicalTextDocument)
            {
                DoCanonicalUpdateByte(b);
            }
            else
            {
                _sig.Update(b);
            }
        }

        /// <summary>
        /// Does the canonical update byte.
        /// </summary>
        /// <param name="b">The b.</param>
        private void DoCanonicalUpdateByte(byte b)
        {
            switch (b)
            {
                case (byte)'\r':
                    DoUpdateCrlf();
                    break;
                case (byte)'\n':
                    if (_lastb != '\r')
                    {
                        DoUpdateCrlf();
                    }
                    break;
                default:
                    _sig.Update(b);
                    break;
            }

            _lastb = b;
        }

        /// <summary>
        /// Does the update CRLF.
        /// </summary>
        private void DoUpdateCrlf()
        {
            _sig.Update((byte)'\r');
            _sig.Update((byte)'\n');
        }

        /// <summary>
        /// Updates the instance with the given data.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        public void Update(params byte[] bytes)
        {
            Update(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Updates the instance with the given data.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <param name="off">The off.</param>
        /// <param name="length">The length.</param>
        public void Update(byte[] bytes, int off, int length)
        {
            if (_signatureType == CanonicalTextDocument)
            {
                var finish = off + length;

                for (var i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                _sig.BlockUpdate(bytes, off, length);
            }
        }

        /// <summary>
        /// Verifies this instance.
        /// </summary>
        /// <returns></returns>
        public bool Verify()
        {
            var trailer = GetSignatureTrailer();
            _sig.BlockUpdate(trailer, 0, trailer.Length);

            return _sig.VerifySignature(GetSignature());
        }

        /// <summary>
        /// Updates the with id data.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <param name="idBytes">The id bytes.</param>
        private void UpdateWithIdData(int header, byte[] idBytes)
        {
            this.Update(
                (byte)header,
                (byte)(idBytes.Length >> 24),
                (byte)(idBytes.Length >> 16),
                (byte)(idBytes.Length >> 8),
                (byte)(idBytes.Length));
            this.Update(idBytes);
        }

        /// <summary>
        /// Updates the with public key.
        /// </summary>
        /// <param name="key">The key.</param>
        private void UpdateWithPublicKey(IPgpPublicKey key)
        {
            var keyBytes = GetEncodedPublicKey(key);

            this.Update(
                (byte)0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length));
            this.Update(keyBytes);
        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in user attributes.
        /// </summary>
        /// <param name="userAttributes">User attributes the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(IPgpUserAttributeSubpacketVector userAttributes, IPgpPublicKey key)
        {
            UpdateWithPublicKey(key);

            //
            // hash in the userAttributes
            //
            try
            {
                using (var bOut = new MemoryStream())
                {
                    foreach (var packet in userAttributes.ToSubpacketArray())
                    {
                        packet.Encode(bOut);
                    }
                    UpdateWithIdData(0xd1, bOut.ToArray());
                }
            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            this.Update(_sigPck.GetSignatureTrailer());

            return _sig.VerifySignature(this.GetSignature());
        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in ID.
        /// </summary>
        /// <param name="id">ID the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(string id, IPgpPublicKey key)
        {
            UpdateWithPublicKey(key);

            //
            // hash in the id
            //
            UpdateWithIdData(0xb4, Strings.ToByteArray(id));

            Update(_sigPck.GetSignatureTrailer());

            return _sig.VerifySignature(GetSignature());
        }

        /// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are verifying against.</param>
        /// <param name="pubKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(IPgpPublicKey masterKey, IPgpPublicKey pubKey)
        {
            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            Update(_sigPck.GetSignatureTrailer());

            return _sig.VerifySignature(GetSignature());
        }

        /// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            IPgpPublicKey pubKey)
        {
            if (SignatureType != KeyRevocation
                && SignatureType != SubkeyRevocation)
            {
                throw new InvalidOperationException("signature is not a key signature");
            }

            UpdateWithPublicKey(pubKey);

            Update(_sigPck.GetSignatureTrailer());

            return _sig.VerifySignature(GetSignature());
        }

        /// <summary>
        /// Gets the type of the signature.
        /// </summary>
        /// <value>
        /// The type of the signature.
        /// </value>
        public int SignatureType
        {
            get { return _sigPck.SignatureType; }
        }

        /// <summary>
        /// The ID of the key that created the signature.
        /// </summary>
        /// <value>
        /// The key id.
        /// </value>
        public long KeyId
        {
            get { return _sigPck.KeyId; }
        }

        /// <summary>
        /// Gets the creation time.
        /// </summary>
        /// <returns></returns>
        [Obsolete("Use 'CreationTime' property instead")]
        public DateTime GetCreationTime()
        {
            return CreationTime;
        }

        /// <summary>
        /// The creation time of this signature.
        /// </summary>
        /// <value>
        /// The creation time.
        /// </value>
        public DateTime CreationTime
        {
            get { return DateTimeUtilities.UnixMsToDateTime(_sigPck.CreationTime); }
        }

        /// <summary>
        /// Gets the signature trailer.
        /// </summary>
        /// <returns></returns>
        public byte[] GetSignatureTrailer()
        {
            return _sigPck.GetSignatureTrailer();
        }

        /// <summary>
        /// Return true if the signature has either hashed or unhashed subpackets.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance has subpackets; otherwise, <c>false</c>.
        /// </value>
        public bool HasSubpackets
        {
            get
            {
                return _sigPck.GetHashedSubPackets() != null
                    || _sigPck.GetUnhashedSubPackets() != null;
            }
        }

        /// <summary>
        /// Gets the hashed sub packets.
        /// </summary>
        /// <returns></returns>
        public IPgpSignatureSubpacketVector GetHashedSubPackets()
        {
            return CreateSubpacketVector(_sigPck.GetHashedSubPackets());
        }

        /// <summary>
        /// Gets the unhashed sub packets.
        /// </summary>
        /// <returns></returns>
        public IPgpSignatureSubpacketVector GetUnhashedSubPackets()
        {
            return CreateSubpacketVector(_sigPck.GetUnhashedSubPackets());
        }

        /// <summary>
        /// Creates the subpacket vector.
        /// </summary>
        /// <param name="pcks">The PCKS.</param>
        /// <returns></returns>
        private static IPgpSignatureSubpacketVector CreateSubpacketVector(ISignatureSubpacket[] pcks)
        {
            return pcks == null ? null : new PgpSignatureSubpacketVector(pcks);
        }

        /// <summary>
        /// Gets the signature.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="PgpException">exception encoding DSA sig.</exception>
        public byte[] GetSignature()
        {
            var sigValues = _sigPck.GetSignature();
            byte[] signature;

            if (sigValues != null)
            {
                if (sigValues.Length == 1)    // an RSA signature
                {
                    signature = sigValues[0].Value.ToByteArrayUnsigned();
                }
                else
                {
                    try
                    {
                        signature = new DerSequence(
                            new DerInteger(sigValues[0].Value),
                            new DerInteger(sigValues[1].Value)).GetEncoded();
                    }
                    catch (IOException e)
                    {
                        throw new PgpException("exception encoding DSA sig.", e);
                    }
                }
            }
            else
            {
                signature = _sigPck.GetSignatureBytes();
            }

            return signature;
        }

        // TODO Handle the encoding stuff by subclassing BcpgObject?
        public byte[] GetEncoded()
        {
            using (var bOut = new MemoryStream())
            {
                Encode(bOut);

                return bOut.ToArray();
            }
        }

        public void Encode(Stream outStream)
        {
            var bcpgOut = BcpgOutputStream.Wrap(outStream);
            bcpgOut.WritePacket(_sigPck);
            if (_trustPck != null)
            {
                bcpgOut.WritePacket(_trustPck);
            }
        }

        /// <summary>
        /// Gets the encoded public key.
        /// </summary>
        /// <param name="pubKey">The pub key.</param>
        /// <returns></returns>
        /// <exception cref="PgpException">exception preparing key.</exception>
        private static byte[] GetEncodedPublicKey(IPgpPublicKey pubKey)
        {
            try
            {
                return pubKey.PublicKeyPacket.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }
        }
    }
}

using System;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Generator for PGP signatures.</remarks>
    // TODO Should be able to implement ISigner?
    public class PgpSignatureGenerator
    {
        private static readonly SignatureSubpacket[] _emptySignatureSubpackets = new SignatureSubpacket[0];

        private readonly PublicKeyAlgorithmTag _keyAlgorithm;
        private readonly HashAlgorithmTag _hashAlgorithm;
        private IPgpPrivateKey _privKey;
        private readonly ISigner _sig;
        private readonly IDigest _dig;
        private int _signatureType;
        private byte _lastb;

        private SignatureSubpacket[] _unhashed = _emptySignatureSubpackets;
        private SignatureSubpacket[] _hashed = _emptySignatureSubpackets;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
        {
            _keyAlgorithm = keyAlgorithm;
            _hashAlgorithm = hashAlgorithm;

            _dig = DigestUtilities.GetDigest(PgpUtilities.GetDigestName(hashAlgorithm));
            _sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(keyAlgorithm, hashAlgorithm));
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int sigType, IPgpPrivateKey key)
        {
            InitSign(sigType, key, null);
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int sigType, IPgpPrivateKey key, SecureRandom random)
        {
            _privKey = key;
            _signatureType = sigType;

            try
            {
                ICipherParameters cp = key.Key;
                if (random != null)
                {
                    cp = new ParametersWithRandom(key.Key, random);
                }

                _sig.Init(true, cp);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

            _dig.Reset();
            _lastb = 0;
        }

        public void Update(byte b)
        {
            if (_signatureType == PgpSignature.CanonicalTextDocument)
            {
                DoCanonicalUpdateByte(b);
            }
            else
            {
                DoUpdateByte(b);
            }
        }

        private void DoCanonicalUpdateByte(
            byte b)
        {
            if (b == '\r')
            {
                DoUpdateCrlf();
            }
            else if (b == '\n')
            {
                if (_lastb != '\r')
                {
                    DoUpdateCrlf();
                }
            }
            else
            {
                DoUpdateByte(b);
            }

            _lastb = b;
        }

        private void DoUpdateCrlf()
        {
            DoUpdateByte((byte)'\r');
            DoUpdateByte((byte)'\n');
        }

        private void DoUpdateByte(
            byte b)
        {
            _sig.Update(b);
            _dig.Update(b);
        }

        public void Update(params byte[] b)
        {
            Update(b, 0, b.Length);
        }

        public void Update(byte[] b, int off, int len)
        {
            if (_signatureType == PgpSignature.CanonicalTextDocument)
            {
                var finish = off + len;

                for (var i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(b[i]);
                }
            }
            else
            {
                _sig.BlockUpdate(b, off, len);
                _dig.BlockUpdate(b, off, len);
            }
        }

        public void SetHashedSubpackets(PgpSignatureSubpacketVector hashedPackets)
        {
            _hashed = hashedPackets == null
                ? _emptySignatureSubpackets
                : hashedPackets.ToSubpacketArray();
        }

        public void SetUnhashedSubpackets(PgpSignatureSubpacketVector unhashedPackets)
        {
            _unhashed = unhashedPackets == null
                ? _emptySignatureSubpackets
                : unhashedPackets.ToSubpacketArray();
        }

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(bool isNested)
        {
            return new PgpOnePassSignature(new OnePassSignaturePacket(
                _signatureType, _hashAlgorithm, _keyAlgorithm, _privKey.KeyId, isNested));
        }

        /// <summary>Return a signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
            SignatureSubpacket[] hPkts = _hashed, unhPkts = _unhashed;
            if (!PacketPresent(_hashed, SignatureSubpacketTag.CreationTime))
            {
                hPkts = InsertSubpacket(hPkts, new SignatureCreationTime(false, DateTime.UtcNow));
            }

            if (!PacketPresent(_hashed, SignatureSubpacketTag.IssuerKeyId)
                && !PacketPresent(_unhashed, SignatureSubpacketTag.IssuerKeyId))
            {
                unhPkts = InsertSubpacket(unhPkts, new IssuerKeyId(false, _privKey.KeyId));
            }

            const int version = 4;
            byte[] hData;

            try
            {
                using (var hOut = new MemoryStream())
                {

                    for (var i = 0; i != hPkts.Length; i++)
                    {
                        hPkts[i].Encode(hOut);
                    }

                    var data = hOut.ToArray();

                    using (var sOut = new MemoryStream(data.Length + 6))
                    {
                        sOut.WriteByte(version);
                        sOut.WriteByte((byte)_signatureType);
                        sOut.WriteByte((byte)_keyAlgorithm);
                        sOut.WriteByte((byte)_hashAlgorithm);
                        sOut.WriteByte((byte)(data.Length >> 8));
                        sOut.WriteByte((byte)data.Length);
                        sOut.Write(data, 0, data.Length);


                        hData = sOut.ToArray();
                    }
                }
            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding hashed data.", e);
            }

            _sig.BlockUpdate(hData, 0, hData.Length);
            _dig.BlockUpdate(hData, 0, hData.Length);

            hData = new byte[]
			{
				version,
				0xff,
				(byte)(hData.Length >> 24),
				(byte)(hData.Length >> 16),
				(byte)(hData.Length >> 8),
				(byte) hData.Length
			};

            _sig.BlockUpdate(hData, 0, hData.Length);
            _dig.BlockUpdate(hData, 0, hData.Length);

            var sigBytes = _sig.GenerateSignature();
            var digest = DigestUtilities.DoFinal(_dig);
            var fingerPrint = new[] { digest[0], digest[1] };

            // an RSA signature
            var isRsa = _keyAlgorithm == PublicKeyAlgorithmTag.RsaSign
                || _keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral;

            var sigValues = isRsa
                ? PgpUtilities.RsaSigToMpi(sigBytes)
                : PgpUtilities.DsaSigToMpi(sigBytes);

            return new PgpSignature(new SignaturePacket(_signatureType, _privKey.KeyId, _keyAlgorithm, _hashAlgorithm, hPkts, unhPkts, fingerPrint, sigValues));
        }

        /// <summary>
        /// Generate a certification for the passed in ID and key.
        /// </summary>
        /// <param name="id">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>
        /// The certification.
        /// </returns>
        public PgpSignature GenerateCertification(string id, IPgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);

            //
            // hash in the id
            //
            UpdateWithIdData(0xb4, Strings.ToByteArray(id));

            return Generate();
        }

        /// <summary>
        /// Generate a certification for the passed in userAttributes.
        /// </summary>
        /// <param name="userAttributes">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>
        /// The certification.
        /// </returns>
        /// <exception cref="PgpException">cannot encode subpacket array</exception>
        public PgpSignature GenerateCertification(PgpUserAttributeSubpacketVector userAttributes, IPgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);

            //
            // hash in the attributes
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

            return this.Generate();
        }

        /// <summary>
        /// Generate a certification for the passed in key against the passed in master key.
        /// </summary>
        /// <param name="masterKey">The key we are certifying against.</param>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>
        /// The certification.
        /// </returns>
        public PgpSignature GenerateCertification(
            IPgpPublicKey masterKey,
            IPgpPublicKey pubKey)
        {
            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            return Generate();
        }

        /// <summary>
        /// Generate a certification, such as a revocation, for the passed in key.
        /// </summary>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>
        /// The certification.
        /// </returns>
        public PgpSignature GenerateCertification(IPgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);

            return Generate();
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

        /// <summary>
        /// Packets the present.
        /// </summary>
        /// <param name="packets">The packets.</param>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        private static bool PacketPresent(SignatureSubpacket[] packets, SignatureSubpacketTag type)
        {
            for (var i = 0; i != packets.Length; i++)
            {
                if (packets[i].SubpacketType == type)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Inserts the subpacket.
        /// </summary>
        /// <param name="packets">The packets.</param>
        /// <param name="subpacket">The subpacket.</param>
        /// <returns></returns>
        private static SignatureSubpacket[] InsertSubpacket(SignatureSubpacket[] packets, SignatureSubpacket subpacket)
        {
            var tmp = new SignatureSubpacket[packets.Length + 1];
            tmp[0] = subpacket;
            packets.CopyTo(tmp, 1);
            return tmp;
        }

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

        private void UpdateWithPublicKey(IPgpPublicKey key)
        {
            var keyBytes = GetEncodedPublicKey(key);
            this.Update(
                (byte)0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length));
            this.Update(keyBytes);
        }
    }
}

using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature
    {
        private readonly OnePassSignaturePacket _sigPack;
        private readonly int _signatureType;
        private ISigner _sig;
        private byte _lastb;

        internal PgpOnePassSignature(
            BcpgInputStream bcpgInput)
            : this((OnePassSignaturePacket)bcpgInput.ReadPacket())
        {
        }

        internal PgpOnePassSignature(
            OnePassSignaturePacket sigPack)
        {
            _sigPack = sigPack;
            _signatureType = sigPack.SignatureType;
        }

        /// <summary>Initialise the signature object for verification.</summary>
        public void InitVerify(IPgpPublicKey pubKey)
        {
            _lastb = 0;

            try
            {
                _sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(_sigPack.KeyAlgorithm, _sigPack.HashAlgorithm));
            }
            catch (Exception e)
            {
                throw new PgpException("can't set up signature object.", e);
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

        public void Update(
            byte b)
        {
            if (_signatureType == PgpSignature.CanonicalTextDocument)
            {
                DoCanonicalUpdateByte(b);
            }
            else
            {
                _sig.Update(b);
            }
        }

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

        private void DoUpdateCrlf()
        {
            _sig.Update((byte)'\r');
            _sig.Update((byte)'\n');
        }

        public void Update(byte[] bytes)
        {
            if (_signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (var i = 0; i != bytes.Length; i++)
                {
                    DoCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                _sig.BlockUpdate(bytes, 0, bytes.Length);
            }
        }

        public void Update(byte[] bytes, int off, int length)
        {
            if (_signatureType == PgpSignature.CanonicalTextDocument)
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
        /// Verify the calculated signature against the passed in PgpSignature.
        /// </summary>
        /// <param name="pgpSig">The PGP sig.</param>
        /// <returns></returns>
        public bool Verify(PgpSignature pgpSig)
        {
            var trailer = pgpSig.GetSignatureTrailer();

            _sig.BlockUpdate(trailer, 0, trailer.Length);

            return _sig.VerifySignature(pgpSig.GetSignature());
        }

        /// <summary>
        /// Gets the key id.
        /// </summary>
        /// <value>
        /// The key id.
        /// </value>
        public long KeyId
        {
            get { return _sigPack.KeyId; }
        }

        /// <summary>
        /// Gets the type of the signature.
        /// </summary>
        /// <value>
        /// The type of the signature.
        /// </value>
        public int SignatureType
        {
            get { return _sigPack.SignatureType; }
        }

        /// <summary>
        /// Gets the hash algorithm.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return _sigPack.HashAlgorithm; }
        }

        /// <summary>
        /// Gets the key algorithm.
        /// </summary>
        /// <value>
        /// The key algorithm.
        /// </value>
        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return _sigPack.KeyAlgorithm; }
        }

        public byte[] GetEncoded()
        {
            using (var bOut = new MemoryStream())
            {
                Encode(bOut);
                return bOut.ToArray();
            }
        }

        public void Encode(Stream outStr)
        {
            var wrap = BcpgOutputStream.Wrap(outStr);
            wrap.WritePacket(_sigPack);            
        }
    }
}

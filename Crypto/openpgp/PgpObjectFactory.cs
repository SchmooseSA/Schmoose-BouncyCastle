using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// General class for reading a PGP object stream.
    /// <p>
    /// Note: if this class finds a PgpPublicKey or a PgpSecretKey it
    /// will create a PgpPublicKeyRing, or a PgpSecretKeyRing for each
    /// key found. If all you are trying to do is read a key ring file use
    /// either PgpPublicKeyRingBundle or PgpSecretKeyRingBundle.</p>
    /// </remarks>
    public class PgpObjectFactory
    {
        private readonly BcpgInputStream _bcpgIn;

        public PgpObjectFactory(
            Stream inputStream)
        {
            _bcpgIn = BcpgInputStream.Wrap(inputStream);
        }

        public PgpObjectFactory(
            byte[] bytes)
            : this(new MemoryStream(bytes, false))
        {
        }

        /// <summary>Return the next object in the stream, or null if the end is reached.</summary>
        /// <exception cref="IOException">On a parse error</exception>
        public PgpObject NextPgpObject()
        {
            var tag = _bcpgIn.NextPacketTag();

            if ((int)tag == -1) return null;

            switch (tag)
            {
                case PacketTag.Signature:
                    {
                        var sigs = new List<PgpSignature>();
                        while (_bcpgIn.NextPacketTag() == PacketTag.Signature)
                        {
                            try
                            {
                                sigs.Add(new PgpSignature(_bcpgIn));
                            }
                            catch (PgpException e)
                            {
                                throw new IOException("can't create signature object: " + e);
                            }
                        }

                        return new PgpSignatureList(sigs.ToArray());
                    }
                case PacketTag.SecretKey:
                    try
                    {
                        return new PgpSecretKeyRing(_bcpgIn);
                    }
                    catch (PgpException e)
                    {
                        throw new IOException("can't create secret key object: " + e);
                    }
                case PacketTag.PublicKey:
                    return new PgpPublicKeyRing(_bcpgIn);
                case PacketTag.CompressedData:
                    return new PgpCompressedData(_bcpgIn);
                case PacketTag.LiteralData:
                    return new PgpLiteralData(_bcpgIn);
                case PacketTag.PublicKeyEncryptedSession:
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new PgpEncryptedDataList(_bcpgIn);
                case PacketTag.OnePassSignature:
                    {
                        var sigs = new List<PgpOnePassSignature>();
                        while (_bcpgIn.NextPacketTag() == PacketTag.OnePassSignature)
                        {
                            try
                            {
                                sigs.Add(new PgpOnePassSignature(_bcpgIn));
                            }
                            catch (PgpException e)
                            {
                                throw new IOException("can't create one pass signature object: " + e);
                            }
                        }

                        return new PgpOnePassSignatureList(sigs.ToArray());
                    }
                case PacketTag.Marker:
                    return new PgpMarker(_bcpgIn);
                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new PgpExperimental(_bcpgIn);
            }

            throw new IOException("unknown object in stream " + _bcpgIn.NextPacketTag());
        }

        [Obsolete("Use NextPgpObject() instead")]
        public object NextObject()
        {
            return NextPgpObject();
        }

        /// <summary>
        /// Return all available objects in a list.
        /// </summary>
        /// <returns>An <c>IList</c> containing all objects from this factory, in order.</returns>
        public IList AllPgpObjects()
        {
            IList result = Platform.CreateArrayList();
            PgpObject pgpObject;
            while ((pgpObject = NextPgpObject()) != null)
            {
                result.Add(pgpObject);
            }
            return result;
        }
    }
}

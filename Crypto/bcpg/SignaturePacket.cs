using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature packet.</remarks>
    public class SignaturePacket : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private readonly int _version;
        private readonly int _signatureType;
        private readonly long _keyId;
        private readonly PublicKeyAlgorithmTag _keyAlgorithm;
        private readonly HashAlgorithmTag _hashAlgorithm;
        private readonly MPInteger[] _signature;
        private readonly byte[] _fingerprint;
        private readonly ISignatureSubpacket[] _hashedData;
        private readonly ISignatureSubpacket[] _unhashedData;
        private readonly byte[] _signatureEncoding;

        internal SignaturePacket(BcpgInputStream bcpgIn)
        {
            _version = bcpgIn.ReadByte();


            //TODO: refactor
            switch (_version)
            {
                case 2:
                case 3:
                    bcpgIn.ReadByte();
                    _signatureType = bcpgIn.ReadByte();
                    CreationTime = (((long)bcpgIn.ReadByte() << 24) | ((long)bcpgIn.ReadByte() << 16)
                                     | ((long)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte()) * 1000L;
                    _keyId |= (long)bcpgIn.ReadByte() << 56;
                    _keyId |= (long)bcpgIn.ReadByte() << 48;
                    _keyId |= (long)bcpgIn.ReadByte() << 40;
                    _keyId |= (long)bcpgIn.ReadByte() << 32;
                    _keyId |= (long)bcpgIn.ReadByte() << 24;
                    _keyId |= (long)bcpgIn.ReadByte() << 16;
                    _keyId |= (long)bcpgIn.ReadByte() << 8;
                    _keyId |= (uint)bcpgIn.ReadByte();
                    _keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();
                    _hashAlgorithm = (HashAlgorithmTag)bcpgIn.ReadByte();
                    break;
                case 4:
                    {
                        _signatureType = bcpgIn.ReadByte();
                        _keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();
                        _hashAlgorithm = (HashAlgorithmTag)bcpgIn.ReadByte();

                        var hashedLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
                        var hashed = new byte[hashedLength];

                        bcpgIn.ReadFully(hashed);

                        //
                        // read the signature sub packet data.
                        //
                        using (var hashedStream = new MemoryStream(hashed, false))
                        {
                            var sIn = new SignatureSubpacketsParser(hashedStream);
                            var v = Platform.CreateArrayList<ISignatureSubpacket>();

                            SignatureSubpacket sub;
                            while ((sub = sIn.ReadPacket()) != null)
                            {
                                v.Add(sub);

                                var issuerKeyId = sub as IssuerKeyId;
                                if (issuerKeyId != null)
                                {
                                    _keyId = issuerKeyId.KeyId;
                                }
                                else
                                {
                                    var signatureCreationTime = sub as SignatureCreationTime;
                                    if (signatureCreationTime != null)
                                    {
                                        CreationTime = DateTimeUtilities.DateTimeToUnixMs(signatureCreationTime.GetTime());
                                    }
                                }
                            }
                            _hashedData = v.ToArray();

                            var unhashedLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
                            var unhashed = new byte[unhashedLength];
                            bcpgIn.ReadFully(unhashed);

                            v.Clear();
                            using (var unhashedStream = new MemoryStream(unhashed, false))
                            {
                                sIn = new SignatureSubpacketsParser(unhashedStream);
                                
                                while ((sub = sIn.ReadPacket()) != null)
                                {
                                    v.Add(sub);

                                    var issuerKeyId = sub as IssuerKeyId;
                                    if (issuerKeyId != null)
                                    {
                                        _keyId = issuerKeyId.KeyId;
                                    }
                                }
                            }
                            _unhashedData = v.ToArray();
                        }
                    }
                    break;
                default:
                    throw new Exception("unsupported version: " + _version);
            }

            _fingerprint = new byte[2];
            bcpgIn.ReadFully(_fingerprint);

            switch (_keyAlgorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    var v = new MPInteger(bcpgIn);
                    _signature = new[] { v };
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                case PublicKeyAlgorithmTag.Ecdsa:
                case PublicKeyAlgorithmTag.Ecdh:  
                    var r = new MPInteger(bcpgIn);
                    var s = new MPInteger(bcpgIn);
                    _signature = new[] { r, s };
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt: // yep, this really does happen sometimes.
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    var p = new MPInteger(bcpgIn);
                    var g = new MPInteger(bcpgIn);
                    var y = new MPInteger(bcpgIn);
                    _signature = new[] { p, g, y };
                    break;                                                  
                default:
                    if (_keyAlgorithm >= PublicKeyAlgorithmTag.Experimental_1 && _keyAlgorithm <= PublicKeyAlgorithmTag.Experimental_11)
                    {
                        _signature = null;
                        using (var bOut = new MemoryStream())
                        {
                            int ch;
                            while ((ch = bcpgIn.ReadByte()) >= 0)
                            {
                                bOut.WriteByte((byte)ch);
                            }
                            _signatureEncoding = bOut.ToArray();
                        }
                    }
                    else
                    {
                        throw new IOException("unknown signature key algorithm: " + _keyAlgorithm);
                    }
                    break;
            }
        }

        /**
        * Generate a version 4 signature packet.
        *
        * @param signatureType
        * @param keyAlgorithm
        * @param hashAlgorithm
        * @param hashedData
        * @param unhashedData
        * @param fingerprint
        * @param signature
        */
        public SignaturePacket(
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            ISignatureSubpacket[] hashedData,
            ISignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            MPInteger[] signature)
            : this(4, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, signature)
        {
        }

        /**
        * Generate a version 2/3 signature packet.
        *
        * @param signatureType
        * @param keyAlgorithm
        * @param hashAlgorithm
        * @param fingerprint
        * @param signature
        */
        public SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            long creationTime,
            byte[] fingerprint,
            MPInteger[] signature)
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, null, null, fingerprint, signature)
        {
            this.CreationTime = creationTime;
        }

        public SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            ISignatureSubpacket[] hashedData,
            ISignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            MPInteger[] signature)
        {
            this._version = version;
            this._signatureType = signatureType;
            this._keyId = keyId;
            this._keyAlgorithm = keyAlgorithm;
            this._hashAlgorithm = hashAlgorithm;
            this._hashedData = hashedData;
            this._unhashedData = unhashedData;
            this._fingerprint = fingerprint;
            this._signature = signature;

            if (hashedData != null)
            {
                SetCreationTime();
            }
        }

        public int Version
        {
            get { return _version; }
        }

        public int SignatureType
        {
            get { return _signatureType; }
        }

        /**
        * return the keyId
        * @return the keyId that created the signature.
        */
        public long KeyId
        {
            get { return _keyId; }
        }

        /**
        * return the signature trailer that must be included with the data
        * to reconstruct the signature
        *
        * @return byte[]
        */
        public byte[] GetSignatureTrailer()
        {
            byte[] trailer;

            if (_version == 3)
            {
                trailer = new byte[5];

                var time = CreationTime / 1000L;

                trailer[0] = (byte)_signatureType;
                trailer[1] = (byte)(time >> 24);
                trailer[2] = (byte)(time >> 16);
                trailer[3] = (byte)(time >> 8);
                trailer[4] = (byte)(time);
            }
            else
            {
                using (var sOut = new MemoryStream())
                {

                    sOut.WriteByte((byte) this.Version);
                    sOut.WriteByte((byte) this.SignatureType);
                    sOut.WriteByte((byte) this.KeyAlgorithm);
                    sOut.WriteByte((byte) this.HashAlgorithm);

                    using (var hOut = new MemoryStream())
                    {
                        var hashed = this.GetHashedSubPackets();
                        for (var i = 0; i != hashed.Length; i++)
                        {
                            hashed[i].Encode(hOut);
                        }

                        var data = hOut.ToArray();

                        sOut.WriteByte((byte) (data.Length >> 8));
                        sOut.WriteByte((byte) data.Length);
                        sOut.Write(data, 0, data.Length);

                        var hData = sOut.ToArray();

                        sOut.WriteByte((byte) this.Version);
                        sOut.WriteByte((byte) 0xff);
                        sOut.WriteByte((byte) (hData.Length >> 24));
                        sOut.WriteByte((byte) (hData.Length >> 16));
                        sOut.WriteByte((byte) (hData.Length >> 8));
                        sOut.WriteByte((byte) (hData.Length));

                        trailer = sOut.ToArray();
                    }
                }
            }

            return trailer;
        }

        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return _keyAlgorithm; }
        }

        public HashAlgorithmTag HashAlgorithm
        {
            get { return _hashAlgorithm; }
        }

        /**
        * return the signature as a set of integers - note this is normalised to be the
        * ASN.1 encoding of what appears in the signature packet.
        */
        public MPInteger[] GetSignature()
        {
            return _signature;
        }

        /**
         * Return the byte encoding of the signature section.
         * @return uninterpreted signature bytes.
         */
        public byte[] GetSignatureBytes()
        {
            if (_signatureEncoding != null)
            {
                return (byte[])_signatureEncoding.Clone();
            }

            using (var bOut = new MemoryStream())
            {
                using (var bcOut = new BcpgOutputStream(bOut))
                {

                    foreach (var sigObj in _signature)
                    {
                        try
                        {
                            bcOut.WriteObject(sigObj);
                        }
                        catch (IOException e)
                        {
                            throw new Exception("internal error: " + e);
                        }
                    }
                }

                return bOut.ToArray();
            }
        }

        public ISignatureSubpacket[] GetHashedSubPackets()
        {
            return _hashedData;
        }

        public ISignatureSubpacket[] GetUnhashedSubPackets()
        {
            return _unhashedData;
        }

        /// <summary>Return the creation time in milliseconds since 1 Jan., 1970 UTC.</summary>
        public long CreationTime { get; private set; }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            using (var bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {

                    pOut.WriteByte((byte)_version);

                    switch (_version)
                    {
                        case 2:
                        case 3:
                            pOut.Write(
                                5, // the length of the next block
                                (byte)_signatureType);
                            pOut.WriteInt((int)(CreationTime / 1000L));
                            pOut.WriteLong(_keyId);
                            pOut.Write(
                                (byte)_keyAlgorithm,
                                (byte)_hashAlgorithm);
                            break;
                        case 4:
                            pOut.Write(
                                (byte)_signatureType,
                                (byte)_keyAlgorithm,
                                (byte)_hashAlgorithm);
                            EncodeLengthAndData(pOut, GetEncodedSubpackets(_hashedData));
                            EncodeLengthAndData(pOut, GetEncodedSubpackets(_unhashedData));
                            break;
                        default:
                            throw new IOException("unknown version: " + _version);
                    }

                    pOut.Write(_fingerprint);

                    if (_signature != null)
                    {
                        pOut.WriteObjects(_signature);
                    }
                    else
                    {
                        pOut.Write(_signatureEncoding);
                    }

                    bcpgOut.WritePacket(PacketTag.Signature, bOut.ToArray(), true);
                }
            }
        }

        private static void EncodeLengthAndData(BcpgOutputStream pOut, byte[] data)
        {
            pOut.WriteShort((short)data.Length);
            pOut.Write(data);
        }

        private static byte[] GetEncodedSubpackets(IEnumerable<ISignatureSubpacket> ps)
        {
            using (var sOut = new MemoryStream())
            {
                foreach (var p in ps)
                {
                    p.Encode(sOut);
                }

                return sOut.ToArray();
            }
        }

        private void SetCreationTime()
        {
            foreach (var data in _hashedData)
            {
                var creationTime = data as SignatureCreationTime;
                if (creationTime == null) 
                    continue;

                CreationTime = DateTimeUtilities.DateTimeToUnixMs(creationTime.GetTime());
                break;
            }
        }
    }
}

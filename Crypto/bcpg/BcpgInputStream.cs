using System;
using System.IO;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Reader for PGP objects.</remarks>
    public class BcpgInputStream : BaseInputStream
    {
        private readonly Stream _mIn;
        private bool _next;
        private int _nextB;

        internal static BcpgInputStream Wrap(Stream inStr)
        {
            var inputStream = inStr as BcpgInputStream;
            return inputStream ?? new BcpgInputStream(inStr);
        }

        private BcpgInputStream(Stream inputStream)
        {
            _mIn = inputStream;
        }

        public override int ReadByte()
        {
            if (_next)
            {
                _next = false;
                return _nextB;
            }

            return _mIn.ReadByte();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Strangely, when count == 0, we should still attempt to read a byte
            //			if (count == 0)
            //				return 0;

            if (!_next)
                return _mIn.Read(buffer, offset, count);

            // We have next byte waiting, so return it

            if (_nextB < 0)
                return 0; // EndOfStream

            if (buffer == null)
                throw new ArgumentNullException("buffer");

            buffer[offset] = (byte)_nextB;
            _next = false;

            return 1;
        }

        public byte[] ReadAll()
        {
            return Streams.ReadAll(this);
        }

        public void ReadFully(byte[] buffer, int off, int len)
        {
            if (Streams.ReadFully(this, buffer, off, len) < len)
                throw new EndOfStreamException();
        }

        public void ReadFully(byte[] buffer)
        {
            ReadFully(buffer, 0, buffer.Length);
        }

        /// <summary>Returns the next packet tag in the stream.</summary>
        public PacketTag NextPacketTag()
        {
            if (!_next)
            {
                try
                {
                    _nextB = _mIn.ReadByte();
                }
                catch (EndOfStreamException)
                {
                    _nextB = -1;
                }

                _next = true;
            }

            if (_nextB >= 0)
            {
                if ((_nextB & 0x40) != 0)    // new
                {
                    return (PacketTag)(_nextB & 0x3f);
                }
                return (PacketTag)((_nextB & 0x3f) >> 2);
            }

            return (PacketTag)_nextB;
        }

        public Packet ReadPacket()
        {
            var hdr = this.ReadByte();

            if (hdr < 0)
            {
                return null;
            }

            if ((hdr & 0x80) == 0)
            {
                throw new IOException("invalid header encountered");
            }

            var newPacket = (hdr & 0x40) != 0;
            PacketTag tag;
            var bodyLen = 0;
            var partial = false;

            if (newPacket)
            {
                tag = (PacketTag)(hdr & 0x3f);

                var l = this.ReadByte();

                if (l < 192)
                {
                    bodyLen = l;
                }
                else if (l <= 223)
                {
                    var b = _mIn.ReadByte();
                    bodyLen = ((l - 192) << 8) + (b) + 192;
                }
                else if (l == 255)
                {
                    bodyLen = (_mIn.ReadByte() << 24)
                        | (_mIn.ReadByte() << 16)
                        | (_mIn.ReadByte() << 8)
                        | _mIn.ReadByte();
                }
                else
                {
                    partial = true;
                    bodyLen = 1 << (l & 0x1f);
                }
            }
            else
            {
                var lengthType = hdr & 0x3;

                tag = (PacketTag)((hdr & 0x3f) >> 2);

                switch (lengthType)
                {
                    case 0:
                        bodyLen = this.ReadByte();
                        break;
                    case 1:
                        bodyLen = (this.ReadByte() << 8) | this.ReadByte();
                        break;
                    case 2:
                        bodyLen = (this.ReadByte() << 24) | (this.ReadByte() << 16)
                            | (this.ReadByte() << 8) | this.ReadByte();
                        break;
                    case 3:
                        partial = true;
                        break;
                    default:
                        throw new IOException("unknown length type encountered");
                }
            }

            BcpgInputStream objStream;
            if (bodyLen == 0 && partial)
            {
                objStream = this;
            }
            else
            {
                objStream = new BcpgInputStream(new PartialInputStream(this, partial, bodyLen));
            }

            switch (tag)
            {
                case PacketTag.Reserved:
                    return new InputStreamPacket(objStream);
                case PacketTag.PublicKeyEncryptedSession:
                    return new PublicKeyEncSessionPacket(objStream);
                case PacketTag.Signature:
                    return new SignaturePacket(objStream);
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new SymmetricKeyEncSessionPacket(objStream);
                case PacketTag.OnePassSignature:
                    return new OnePassSignaturePacket(objStream);
                case PacketTag.SecretKey:
                    return new SecretKeyPacket(objStream);
                case PacketTag.PublicKey:
                    return new PublicKeyPacket(objStream);
                case PacketTag.SecretSubkey:
                    return new SecretSubkeyPacket(objStream);
                case PacketTag.CompressedData:
                    return new CompressedDataPacket(objStream);
                case PacketTag.SymmetricKeyEncrypted:
                    return new SymmetricEncDataPacket(objStream);
                case PacketTag.Marker:
                    return new MarkerPacket(objStream);
                case PacketTag.LiteralData:
                    return new LiteralDataPacket(objStream);
                case PacketTag.Trust:
                    return new TrustPacket(objStream);
                case PacketTag.UserId:
                    return new UserIdPacket(objStream);
                case PacketTag.UserAttribute:
                    return new UserAttributePacket(objStream);
                case PacketTag.PublicSubkey:
                    return new PublicSubkeyPacket(objStream);
                case PacketTag.SymmetricEncryptedIntegrityProtected:
                    return new SymmetricEncIntegrityPacket(objStream);
                case PacketTag.ModificationDetectionCode:
                    return new ModDetectionCodePacket(objStream);
                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new ExperimentalPacket(tag, objStream);
                default:
                    throw new IOException("unknown packet type encountered: " + tag);
            }
        }
        #if !NETFX_CORE
        public override void Close()
        {
            _mIn.Close();
            base.Close();
        }
#else
        protected override void Dispose(bool disposing)
        {
            _mIn.Dispose();
            base.Dispose(disposing);
        }
#endif

        /// <summary>
        /// A stream that overlays our input stream, allowing the user to only read a segment of it.
        /// NB: dataLength will be negative if the segment length is in the upper range above 2**31.
        /// </summary>
        private class PartialInputStream : BaseInputStream
        {
            private readonly BcpgInputStream _in;
            private bool _partial;
            private int _dataLength;

            internal PartialInputStream(BcpgInputStream bcpgIn, bool partial, int dataLength)
            {
                _in = bcpgIn;
                _partial = partial;
                _dataLength = dataLength;
            }

            public override int ReadByte()
            {
                do
                {
                    if (_dataLength == 0) 
                        continue;
                    
                    var ch = _in.ReadByte();
                    if (ch < 0)                    
                        throw new EndOfStreamException("Premature end of stream in PartialInputStream");                    
                    _dataLength--;
                    return ch;
                }
                while (_partial && ReadPartialDataLength() >= 0);

                return -1;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                do
                {
                    if (_dataLength == 0) 
                        continue;

                    var readLen = (_dataLength > count || _dataLength < 0) ? count : _dataLength;
                    var len = _in.Read(buffer, offset, readLen);
                    if (len < 1)                    
                        throw new EndOfStreamException("Premature end of stream in PartialInputStream");                    
                    _dataLength -= len;
                    return len;
                }
                while (_partial && ReadPartialDataLength() >= 0);

                return 0;
            }

            private int ReadPartialDataLength()
            {
                var l = _in.ReadByte();

                if (l < 0)
                {
                    return -1;
                }

                _partial = false;

                if (l < 192)
                {
                    _dataLength = l;
                }
                else if (l <= 223)
                {
                    _dataLength = ((l - 192) << 8) + (_in.ReadByte()) + 192;
                }
                else if (l == 255)
                {
                    _dataLength = (_in.ReadByte() << 24) | (_in.ReadByte() << 16)
                        | (_in.ReadByte() << 8) | _in.ReadByte();
                }
                else
                {
                    _partial = true;
                    _dataLength = 1 << (l & 0x1f);
                }

                return 0;
            }
        }
    }
}

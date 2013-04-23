using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic output stream.</remarks>
    public class BcpgOutputStream : BaseOutputStream, IBcpgOutputStream
    {
        internal static BcpgOutputStream Wrap(Stream outStr)
        {
            var bcpg = outStr as BcpgOutputStream;
            return bcpg ?? new BcpgOutputStream(outStr);
        }

        private readonly Stream _outStr;
        private byte[] _partialBuffer;
        private readonly int _partialBufferLength;
        private readonly int _partialPower;
        private int _partialOffset;
        private const int BufferSizePower = 16; // 2^16 size buffer on long files

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        public BcpgOutputStream(Stream outStr)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            _outStr = outStr;
        }

        /// <summary>Create a stream representing an old style partial object.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">The packet tag for the object.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            _outStr = outStr;
            this.WriteHeader(tag, true, true, 0);
        }

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="length">Size of chunks making up the packet.</param>
        /// <param name="oldFormat">If true, the header is written out in old format.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, long length, bool oldFormat)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            _outStr = outStr;

            if (length > 0xFFFFFFFFL)
            {
                this.WriteHeader(tag, false, true, 0);
                _partialBufferLength = 1 << BufferSizePower;
                _partialBuffer = new byte[_partialBufferLength];
                _partialPower = BufferSizePower;
                _partialOffset = 0;
            }
            else
            {
                this.WriteHeader(tag, oldFormat, false, length);
            }
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="length">Size of chunks making up the packet.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, long length)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            _outStr = outStr;
            this.WriteHeader(tag, false, false, length);
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="buffer">Buffer to use for collecting chunks.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, byte[] buffer)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            _outStr = outStr;
            this.WriteHeader(tag, false, true, 0);

            _partialBuffer = buffer;

            var length = (uint)_partialBuffer.Length;
            for (_partialPower = 0; length != 1; _partialPower++)
            {
                length >>= 1;
            }

            if (_partialPower > 30)
            {
                throw new IOException("Buffer cannot be greater than 2^30 in length.");
            }
            _partialBufferLength = 1 << _partialPower;
            _partialOffset = 0;
        }

        private void WriteNewPacketLength(long bodyLen)
        {
            if (bodyLen < 192)
            {
                _outStr.WriteByte((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                _outStr.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                _outStr.WriteByte((byte)bodyLen);
            }
            else
            {
                _outStr.WriteByte(0xff);
                _outStr.WriteByte((byte)(bodyLen >> 24));
                _outStr.WriteByte((byte)(bodyLen >> 16));
                _outStr.WriteByte((byte)(bodyLen >> 8));
                _outStr.WriteByte((byte)bodyLen);
            }
        }

        private void WriteHeader(PacketTag tag, bool oldPackets, bool partial, long bodyLen)
        {
            var hdr = 0x80;
            if (_partialBuffer != null)
            {
                PartialFlush(true);
                _partialBuffer = null;
            }

            if (oldPackets)
            {
                hdr |= ((int)tag) << 2;

                if (partial)
                {
                    this.WriteByte((byte)(hdr | 0x03));
                }
                else
                {
                    if (bodyLen <= 0xff)
                    {
                        this.WriteByte((byte)hdr);
                        this.WriteByte((byte)bodyLen);
                    }
                    else if (bodyLen <= 0xffff)
                    {
                        this.WriteByte((byte)(hdr | 0x01));
                        this.WriteByte((byte)(bodyLen >> 8));
                        this.WriteByte((byte)(bodyLen));
                    }
                    else
                    {
                        this.WriteByte((byte)(hdr | 0x02));
                        this.WriteByte((byte)(bodyLen >> 24));
                        this.WriteByte((byte)(bodyLen >> 16));
                        this.WriteByte((byte)(bodyLen >> 8));
                        this.WriteByte((byte)bodyLen);
                    }
                }
            }
            else
            {
                hdr |= 0x40 | (int)tag;
                this.WriteByte((byte)hdr);

                if (partial)
                {
                    _partialOffset = 0;
                }
                else
                {
                    this.WriteNewPacketLength(bodyLen);
                }
            }
        }

        private void PartialFlush(bool isLast)
        {
            if (isLast)
            {
                WriteNewPacketLength(_partialOffset);
                _outStr.Write(_partialBuffer, 0, _partialOffset);
            }
            else
            {
                _outStr.WriteByte((byte)(0xE0 | _partialPower));
                _outStr.Write(_partialBuffer, 0, _partialBufferLength);
            }

            _partialOffset = 0;
        }

        private void WritePartial(byte b)
        {
            if (_partialOffset == _partialBufferLength)
            {
                PartialFlush(false);
            }

            _partialBuffer[_partialOffset++] = b;
        }

        private void WritePartial(byte[] buffer, int off, int len)
        {
            if (_partialOffset == _partialBufferLength)
            {
                PartialFlush(false);
            }

            if (len <= (_partialBufferLength - _partialOffset))
            {
                Array.Copy(buffer, off, _partialBuffer, _partialOffset, len);
                _partialOffset += len;
            }
            else
            {
                var diff = _partialBufferLength - _partialOffset;
                Array.Copy(buffer, off, _partialBuffer, _partialOffset, diff);
                off += diff;
                len -= diff;
                PartialFlush(false);
                while (len > _partialBufferLength)
                {
                    Array.Copy(buffer, off, _partialBuffer, 0, _partialBufferLength);
                    off += _partialBufferLength;
                    len -= _partialBufferLength;
                    PartialFlush(false);
                }
                Array.Copy(buffer, off, _partialBuffer, 0, len);
                _partialOffset += len;
            }
        }

        public override void WriteByte(byte value)
        {
            if (_partialBuffer != null)
            {
                WritePartial(value);
            }
            else
            {
                _outStr.WriteByte(value);
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_partialBuffer != null)
            {
                WritePartial(buffer, offset, count);
            }
            else
            {
                _outStr.Write(buffer, offset, count);
            }
        }

        // Additional helper methods to write primitive types
        public virtual void WriteShort(short n)
        {
            this.Write((byte)(n >> 8), (byte)n);
        }

        public virtual void WriteInt(int n)
        {
            this.Write((byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n);
        }

        public virtual void WriteLong(long n)
        {
            this.Write(
                (byte)(n >> 56),
                (byte)(n >> 48),
                (byte)(n >> 40),
                (byte)(n >> 32),
                (byte)(n >> 24),
                (byte)(n >> 16),
                (byte)(n >> 8),
                (byte)n);
        }

        public void WritePacket(IContainedPacket p)
        {
            p.Encode(this);
        }

        public void WritePacket(PacketTag tag, byte[] body, bool oldFormat)
        {
            this.WriteHeader(tag, oldFormat, false, body.Length);
            this.Write(body);
        }

        public void WriteObject(IBcpgObject bcpgObject)
        {
            bcpgObject.Encode(this);
        }

        public void WriteObjects(params IBcpgObject[] v)
        {
            foreach (BcpgObject o in v)
            {
                o.Encode(this);
            }
        }

        /// <summary>Flush the underlying stream.</summary>
        public override void Flush()
        {
            _outStr.Flush();
        }

        /// <summary>Finish writing out the current packet without closing the underlying stream.</summary>
        public void Finish()
        {
            if (_partialBuffer != null)
            {
                PartialFlush(true);
                _partialBuffer = null;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)            
                _outStr.Dispose();            
            base.Dispose(disposing);
        }

        public override void Close()
        {
            this.Finish();
            _outStr.Flush();
            _outStr.Close();
            base.Close();
        }
    }
}

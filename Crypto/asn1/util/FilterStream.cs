using System;
using System.IO;

namespace Org.BouncyCastle.Asn1.Utilities
{
    public class FilterStream : Stream
    {
        public FilterStream(Stream s)
        {
            this.S = s;
        }
        public override bool CanRead
        {
            get { return S.CanRead; }
        }
        public override bool CanSeek
        {
            get { return S.CanSeek; }
        }
        public override bool CanWrite
        {
            get { return S.CanWrite; }
        }
        public override long Length
        {
            get { return S.Length; }
        }
        public override long Position
        {
            get { return S.Position; }
            set { S.Position = value; }
        }
        #if !NETFX_CORE
        public override void Close()
        {
            S.Close();
        }
#else
        protected override void Dispose(bool disposing)
        {
            try
            {
                S.Dispose();
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
#endif
        public override void Flush()
        {
            S.Flush();
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            return S.Seek(offset, origin);
        }
        public override void SetLength(long value)
        {
            S.SetLength(value);
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            return S.Read(buffer, offset, count);
        }
        public override int ReadByte()
        {
            return S.ReadByte();
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            S.Write(buffer, offset, count);
        }
        public override void WriteByte(byte value)
        {
            S.WriteByte(value);
        }
        protected readonly Stream S;
    }
}

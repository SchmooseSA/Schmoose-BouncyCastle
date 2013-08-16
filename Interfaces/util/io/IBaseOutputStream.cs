using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    public interface IBaseOutputStream : IDisposable
    {
        bool CanRead { get; }
        bool CanSeek { get; }
        bool CanWrite { get; }
        long Length { get; }
        long Position { get; set; }
        bool CanTimeout { get; }
        int ReadTimeout { get; set; }
        int WriteTimeout { get; set; }
#if !NETFX_CORE
        void Close();
#endif
        void Flush();
        int Read(byte[] buffer, int offset, int count);
        long Seek(long offset, SeekOrigin origin);
        void SetLength(long value);
        void Write(byte[] buffer, int offset, int count);
        void Write(params byte[] buffer);
        void CopyTo(Stream destination);
        void CopyTo(Stream destination, int bufferSize);        
        int ReadByte();
        void WriteByte(byte value);
    }
}
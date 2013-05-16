using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.Attr
{
    /// <remarks>Basic type for a image attribute packet.</remarks>
    public class ImageAttribute : UserAttributeSubpacket, IImageAttribute
    {
        public enum Format : byte
        {
            Jpeg = 1
        }

        private static readonly byte[] _zeroes = new byte[12];

        private readonly int _hdrLength;
        private readonly int _version;
        private readonly int _encoding;
        private readonly byte[] _imageData;

        public ImageAttribute(byte[] data)
            : base(UserAttributeSubpacketTag.ImageAttribute, data)
        {
            _hdrLength = ((data[1] & 0xff) << 8) | (data[0] & 0xff);
            _version = data[2] & 0xff;
            _encoding = data[3] & 0xff;

            _imageData = new byte[data.Length - _hdrLength];
            Array.Copy(data, _hdrLength, _imageData, 0, _imageData.Length);
        }

        public ImageAttribute(Format imageType, byte[] imageData)
            : this(ToByteArray(imageType, imageData))
        {
        }

        private static byte[] ToByteArray(Format imageType, byte[] imageData)
        {
            using (var bOut = new MemoryStream())
            {
                bOut.WriteByte(0x10);
                bOut.WriteByte(0x00);
                bOut.WriteByte(0x01);
                bOut.WriteByte((byte) imageType);
                bOut.Write(_zeroes, 0, _zeroes.Length);
                bOut.Write(imageData, 0, imageData.Length);
                return bOut.ToArray();
            }
        }

        public int Version
        {
            get { return _version; }
        }

        public int Encoding
        {
            get { return _encoding; }
        }

        public byte[] GetImageData()
        {
            return _imageData;
        }
    }
}

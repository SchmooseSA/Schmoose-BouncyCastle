using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.Attr
{
    public enum SchmooseContentType : byte
    {
        EmailAddress = 0,
        PhoneNumber = 1,
        Identity = 2,
        FullName = 3
    }

    public enum SchmooseContentDisposition : byte
    {
        Plain = 0,
        Hashed = 1
    }

    public class SchmooseAttribute : UserAttributeSubpacket
    {        
        public SchmooseAttribute(byte[] data)
            : base(UserAttributeSubpacketTag.SchmooseAttribute, data)
        {
            var pos = 0;

            this.ContentType = (SchmooseContentType)data[pos++];
            this.ContentDisposition = (SchmooseContentDisposition)data[pos++];

            var length = data[pos++];
            var contentLen = length < 0xFF ? length : (data[pos++] << 24) | (data[pos++] << 16) | (data[pos++] << 8) | data[pos++];                        
            if(contentLen + pos >= data.Length)
                throw new IOException("data too long.");

            this.ContentValue = contentLen > 0 ? Encoding.UTF8.GetString(data, pos, contentLen) : string.Empty;
        }

        public SchmooseAttribute(SchmooseContentType contentType, SchmooseContentDisposition contentDisposition, string value)
            : base(UserAttributeSubpacketTag.SchmooseAttribute, null)
        {
            this.ContentType = contentType;
            this.ContentDisposition = contentDisposition;
            this.ContentValue = value ?? string.Empty;

            using (var stream = new MemoryStream())
            {
                stream.WriteByte((byte)this.ContentType);
                stream.WriteByte((byte)this.ContentDisposition);

                var utf8 = Encoding.UTF8.GetBytes(this.ContentValue);
                if (utf8.Length < 0xFF)
                {
                    stream.WriteByte((byte)utf8.Length);
                }
                else
                {
                    stream.WriteByte(0xFF);
                    stream.WriteByte((byte)(utf8.Length >> 24));
                    stream.WriteByte((byte)(utf8.Length >> 16));
                    stream.WriteByte((byte)(utf8.Length >> 8));
                    stream.WriteByte((byte)utf8.Length);
                }
                stream.Write(utf8, 0, utf8.Length);

                this.Data = stream.ToArray();
            }
        }

        public SchmooseContentType ContentType { get; private set; }

        public SchmooseContentDisposition ContentDisposition { get; private set; }

        public string ContentValue { get; private set; }
    }
}

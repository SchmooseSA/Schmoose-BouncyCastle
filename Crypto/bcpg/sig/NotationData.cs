using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * Class provided a NotationData object according to
    * RFC2440, Chapter 5.2.3.15. Notation Data
    */
    public class NotationData : SignatureSubpacket, INotationData
    {
        public const int HeaderFlagLength = 4;
        public const int HeaderNameLength = 2;
        public const int HeaderValueLength = 2;

        public NotationData(bool critical, byte[] data)
            : base(SignatureSubpacketTag.NotationData, critical, data) { }

        public NotationData(bool critical, bool humanReadable, string notationName, string notationValue)
            : base(SignatureSubpacketTag.NotationData, critical, CreateData(humanReadable, notationName, notationValue)) { }

        private static byte[] CreateData(bool humanReadable,string notationName,string notationValue)
        {
            using (var os = new MemoryStream())
            {

                // (4 octets of flags, 2 octets of name length (M),
                // 2 octets of value length (N),
                // M octets of name data,
                // N octets of value data)

                // flags
                os.WriteByte(humanReadable ? (byte) 0x80 : (byte) 0x00);
                os.WriteByte(0x0);
                os.WriteByte(0x0);
                os.WriteByte(0x0);

                var nameData = Encoding.UTF8.GetBytes(notationName);
                var nameLength = System.Math.Min(nameData.Length, 0xFF);

                var valueData = Encoding.UTF8.GetBytes(notationValue);
                var valueLength = System.Math.Min(valueData.Length, 0xFF);

                // name length
                os.WriteByte((byte) (nameLength >> 8));
                os.WriteByte((byte) (nameLength >> 0));

                // value length
                os.WriteByte((byte) (valueLength >> 8));
                os.WriteByte((byte) (valueLength >> 0));

                // name
                os.Write(nameData, 0, nameLength);

                // value
                os.Write(valueData, 0, valueLength);

                return os.ToArray();
            }
        }

        public bool IsHumanReadable
        {
            get { return Data[0] == 0x80; }
        }

        public string GetNotationName()
        {
            var nameLength = ((Data[HeaderFlagLength] << 8) + (Data[HeaderFlagLength + 1] << 0));
            const int namePos = HeaderFlagLength + HeaderNameLength + HeaderValueLength;

            return Encoding.UTF8.GetString(Data, namePos, nameLength);
        }

        public string GetNotationValue()
        {
            var nameLength = ((Data[HeaderFlagLength] << 8) + (Data[HeaderFlagLength + 1] << 0));
            var valueLength = ((Data[HeaderFlagLength + HeaderNameLength] << 8) + (Data[HeaderFlagLength + HeaderNameLength + 1] << 0));
            var valuePos = HeaderFlagLength + HeaderNameLength + HeaderValueLength + nameLength;

            return Encoding.UTF8.GetString(Data, valuePos, valueLength);
        }

        public byte[] GetNotationValueBytes()
        {
            var nameLength = ((Data[HeaderFlagLength] << 8) + (Data[HeaderFlagLength + 1] << 0));
            var valueLength = ((Data[HeaderFlagLength + HeaderNameLength] << 8) + (Data[HeaderFlagLength + HeaderNameLength + 1] << 0));
            var valuePos = HeaderFlagLength + HeaderNameLength + HeaderValueLength + nameLength;

            var bytes = new byte[valueLength];
            Array.Copy(Data, valuePos, bytes, 0, valueLength);
            return bytes;
        }
    }
}

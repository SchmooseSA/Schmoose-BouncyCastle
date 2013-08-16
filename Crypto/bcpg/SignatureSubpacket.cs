using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a PGP Signature sub-packet.</remarks>
    public class SignatureSubpacket : ISignatureSubpacket
    {
        private readonly SignatureSubpacketTag _type;
        private readonly bool _critical;

        internal readonly byte[] Data;

        protected internal SignatureSubpacket(SignatureSubpacketTag type, bool critical, byte[] data)
        {
            this._type = type;
            this._critical = critical;
            this.Data = data;
        }

        public SignatureSubpacketTag SubpacketType
        {
            get { return _type; }
        }

        public bool IsCritical()
        {
            return _critical;
        }

        /// <summary>Return the generic data making up the packet.</summary>
        public byte[] GetData()
        {
            return (byte[])Data.Clone();
        }

        public void Encode(Stream os)
        {
            var bodyLen = Data.Length + 1;

            if (bodyLen < 192)
            {
                os.WriteByte((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                os.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                os.WriteByte((byte)bodyLen);
            }
            else
            {
                os.WriteByte(0xff);
                os.WriteByte((byte)(bodyLen >> 24));
                os.WriteByte((byte)(bodyLen >> 16));
                os.WriteByte((byte)(bodyLen >> 8));
                os.WriteByte((byte)bodyLen);
            }

            if (_critical)
            {
                os.WriteByte((byte)(0x80 | (int)_type));
            }
            else
            {
                os.WriteByte((byte)_type);
            }

            os.Write(Data, 0, Data.Length);
        }
    }
}

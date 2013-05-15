using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a user attribute sub-packet.
    */
    public class UserAttributeSubpacket : IUserAttributeSubpacket
    {
        private readonly UserAttributeSubpacketTag _type;
        private byte[] _data;

        internal UserAttributeSubpacket(UserAttributeSubpacketTag type, byte[] data)
        {
            _type = type;
            _data = data;
        }

        public UserAttributeSubpacketTag SubpacketType
        {
            get { return _type; }
        }

        /**
        * return the generic data making up the packet.
        */
        
        [Obsolete("use Data")]
        public byte[] GetData()
        {
            return this.Data;
        }

        public byte[] Data 
        {
            get { return _data; }
            protected set { _data = value; }
        }
        
        public void Encode(Stream os)
        {
            var bodyLen = _data.Length + 1;

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

            os.WriteByte((byte)_type);
            os.Write(_data, 0, _data.Length);
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as UserAttributeSubpacket;
            if (other == null)
                return false;
            return _type == other.SubpacketType && Arrays.AreEqual(_data, other.Data);
        }

        public override int GetHashCode()
        {
            return _type.GetHashCode() ^ Arrays.GetHashCode(this.Data);
        }
    }
}

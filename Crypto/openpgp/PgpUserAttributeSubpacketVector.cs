using System.Linq;
using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Container for a list of user attribute subpackets.</remarks>
    public class PgpUserAttributeSubpacketVector : IPgpUserAttributeSubpacketVector
	{
        private readonly IUserAttributeSubpacket[] _packets;

		internal PgpUserAttributeSubpacketVector(IUserAttributeSubpacket[] packets)
        {
            _packets = packets;
        }

		public IUserAttributeSubpacket GetSubpacket(UserAttributeSubpacketTag type)
        {
            for (var i = 0; i != _packets.Length; i++)
            {
                if (_packets[i].SubpacketType == type)
                {
                    return _packets[i];
                }
            }

			return null;
        }

		public IImageAttrib GetImageAttribute()
        {
            var p = GetSubpacket(UserAttributeSubpacketTag.ImageAttribute);

            return p == null ? null : (IImageAttrib) p;
        }

        internal IUserAttributeSubpacket[] ToSubpacketArray()
        {
            return _packets;
        }

		public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

			var other = obj as PgpUserAttributeSubpacketVector;

			if (other == null)
				return false;

			if (other._packets.Length != _packets.Length)
            {
                return false;
            }

			for (var i = 0; i != _packets.Length; i++)
            {
                if (!other._packets[i].Equals(_packets[i]))
                {
                    return false;
                }
            }

			return true;
        }

		public override int GetHashCode()
		{
		    return _packets.Cast<object>().Aggregate(0, (current, o) => current ^ o.GetHashCode());
		}
	}
}

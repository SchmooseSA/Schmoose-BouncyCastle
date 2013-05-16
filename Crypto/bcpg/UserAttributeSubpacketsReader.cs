using System.IO;
using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
	/**
	* reader for user attribute sub-packets
	*/
	public class UserAttributeSubpacketsParser
	{
		private readonly Stream _input;

		public UserAttributeSubpacketsParser(Stream input)
		{
			_input = input;
		}

		public UserAttributeSubpacket ReadPacket()
		{
			var l = _input.ReadByte();
			if (l < 0)
				return null;

			var bodyLen = 0;
			if (l < 192)
			{
				bodyLen = l;
			}
			else if (l <= 223)
			{
				bodyLen = ((l - 192) << 8) + (_input.ReadByte()) + 192;
			}
			else if (l == 255)
			{
				bodyLen = (_input.ReadByte() << 24) | (_input.ReadByte() << 16)
					|  (_input.ReadByte() << 8)  | _input.ReadByte();
			}
			else
			{
				// TODO Error?
			}

			var tag = _input.ReadByte();
			if (tag < 0)
				throw new EndOfStreamException("unexpected EOF reading user attribute sub packet");

			var data = new byte[bodyLen - 1];
			if (Streams.ReadFully(_input, data) < data.Length)
				throw new EndOfStreamException();

			var type = (UserAttributeSubpacketTag) tag;
			switch (type)
			{
				case UserAttributeSubpacketTag.ImageAttribute:
					return new ImageAttribute(data);

                case UserAttributeSubpacketTag.Experimental_1:
                case UserAttributeSubpacketTag.Experimental_2:
                case UserAttributeSubpacketTag.Experimental_3:
                case UserAttributeSubpacketTag.Experimental_4:
                case UserAttributeSubpacketTag.Experimental_5:
                case UserAttributeSubpacketTag.Experimental_6:
                case UserAttributeSubpacketTag.Experimental_7:
                case UserAttributeSubpacketTag.Experimental_8:
                case UserAttributeSubpacketTag.Experimental_9:
                case UserAttributeSubpacketTag.Experimental_10:
                case UserAttributeSubpacketTag.Experimental_11:
                    return new ExperimentalAttribute(type, data);

                default:
                    return new UserAttributeSubpacket(type, data);
			}			
		}
	}
}

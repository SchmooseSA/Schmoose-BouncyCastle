using System.IO;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
	/**
	* reader for signature sub-packets
	*/
	public class SignatureSubpacketsParser
	{
		private readonly Stream _input;

		public SignatureSubpacketsParser(Stream input)
		{
			_input = input;
		}

		public SignatureSubpacket ReadPacket()
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
				throw new EndOfStreamException("unexpected EOF reading signature sub packet");

			var data = new byte[bodyLen - 1];
			if (Streams.ReadFully(_input, data) < data.Length)
				throw new EndOfStreamException();

			var isCritical = ((tag & 0x80) != 0);
			var type = (SignatureSubpacketTag)(tag & 0x7f);
			switch (type)
			{
				case SignatureSubpacketTag.CreationTime:
					return new SignatureCreationTime(isCritical, data);
				case SignatureSubpacketTag.KeyExpireTime:
					return new KeyExpirationTime(isCritical, data);
				case SignatureSubpacketTag.ExpireTime:
					return new SignatureExpirationTime(isCritical, data);
				case SignatureSubpacketTag.Revocable:
					return new Revocable(isCritical, data);
				case SignatureSubpacketTag.Exportable:
					return new Exportable(isCritical, data);
				case SignatureSubpacketTag.IssuerKeyId:
					return new IssuerKeyId(isCritical, data);
				case SignatureSubpacketTag.TrustSig:
					return new TrustSignature(isCritical, data);
				case SignatureSubpacketTag.PreferredCompressionAlgorithms:
				case SignatureSubpacketTag.PreferredHashAlgorithms:
				case SignatureSubpacketTag.PreferredSymmetricAlgorithms:
					return new PreferredAlgorithms(type, isCritical, data);
				case SignatureSubpacketTag.KeyFlags:
					return new KeyFlags(isCritical, data);
				case SignatureSubpacketTag.PrimaryUserId:
					return new PrimaryUserId(isCritical, data);
				case SignatureSubpacketTag.SignerUserId:
					return new SignerUserId(isCritical, data);
				case SignatureSubpacketTag.NotationData:
					return new NotationData(isCritical, data);
			}
			return new SignatureSubpacket(type, isCritical, data);
		}
	}
}

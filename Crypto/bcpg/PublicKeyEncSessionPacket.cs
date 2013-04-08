using System;
using System.IO;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for a PGP public key.</remarks>
	public class PublicKeyEncSessionPacket
		: ContainedPacket //, PublicKeyAlgorithmTag
	{
		private readonly int _version;
		private readonly long _keyId;
		private readonly PublicKeyAlgorithmTag _algorithm;
        private readonly IBigInteger[] _data;

		internal PublicKeyEncSessionPacket(
			BcpgInputStream bcpgIn)
		{
			_version = bcpgIn.ReadByte();

			_keyId |= (long)bcpgIn.ReadByte() << 56;
			_keyId |= (long)bcpgIn.ReadByte() << 48;
			_keyId |= (long)bcpgIn.ReadByte() << 40;
			_keyId |= (long)bcpgIn.ReadByte() << 32;
			_keyId |= (long)bcpgIn.ReadByte() << 24;
			_keyId |= (long)bcpgIn.ReadByte() << 16;
			_keyId |= (long)bcpgIn.ReadByte() << 8;
			_keyId |= (uint)bcpgIn.ReadByte();

			_algorithm = (PublicKeyAlgorithmTag) bcpgIn.ReadByte();

			switch (_algorithm)
			{
				case PublicKeyAlgorithmTag.RsaEncrypt:
				case PublicKeyAlgorithmTag.RsaGeneral:
                    _data = new[] { new MPInteger(bcpgIn).Value };
					break;
				case PublicKeyAlgorithmTag.ElGamalEncrypt:
				case PublicKeyAlgorithmTag.ElGamalGeneral:
                    _data = new[]
					{
						new MPInteger(bcpgIn).Value,
						new MPInteger(bcpgIn).Value
					};
					break;
				default:
					throw new IOException("unknown PGP public key algorithm encountered");
			}
		}

		public PublicKeyEncSessionPacket(
			long					keyId,
			PublicKeyAlgorithmTag	algorithm,
			BigInteger[]			data)
		{
			this._version = 3;
			this._keyId = keyId;
			this._algorithm = algorithm;
            this._data = (IBigInteger[])data.Clone();
		}

		public int Version
		{
			get { return _version; }
		}

		public long KeyId
		{
			get { return _keyId; }
		}

		public PublicKeyAlgorithmTag Algorithm
		{
			get { return _algorithm; }
		}

        public IBigInteger[] GetEncSessionKey()
		{
            return (IBigInteger[])_data.Clone();
		}

		public override void Encode(
			IBcpgOutputStream bcpgOut)
		{
		    using (var bOut = new MemoryStream())
		    {
		        using (var pOut = new BcpgOutputStream(bOut))
		        {

		            pOut.WriteByte((byte) _version);

		            pOut.WriteLong(_keyId);

		            pOut.WriteByte((byte) _algorithm);

		            for (var i = 0; i != _data.Length; i++)
		            {
		                MPInteger.Encode(pOut, _data[i]);
		            }

		            bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession, bOut.ToArray(), true);
		        }
		    }
		}
	}
}

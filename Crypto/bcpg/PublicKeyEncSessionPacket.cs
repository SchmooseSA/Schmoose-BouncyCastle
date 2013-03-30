using System;
using System.IO;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for a PGP public key.</remarks>
	public class PublicKeyEncSessionPacket
		: ContainedPacket //, PublicKeyAlgorithmTag
	{
		private int version;
		private long keyId;
		private PublicKeyAlgorithmTag algorithm;
        private IBigInteger[] data;

		internal PublicKeyEncSessionPacket(
			BcpgInputStream bcpgIn)
		{
			version = bcpgIn.ReadByte();

			keyId |= (long)bcpgIn.ReadByte() << 56;
			keyId |= (long)bcpgIn.ReadByte() << 48;
			keyId |= (long)bcpgIn.ReadByte() << 40;
			keyId |= (long)bcpgIn.ReadByte() << 32;
			keyId |= (long)bcpgIn.ReadByte() << 24;
			keyId |= (long)bcpgIn.ReadByte() << 16;
			keyId |= (long)bcpgIn.ReadByte() << 8;
			keyId |= (uint)bcpgIn.ReadByte();

			algorithm = (PublicKeyAlgorithmTag) bcpgIn.ReadByte();

			switch ((PublicKeyAlgorithmTag) algorithm)
			{
				case PublicKeyAlgorithmTag.RsaEncrypt:
				case PublicKeyAlgorithmTag.RsaGeneral:
                    data = new IBigInteger[] { new MPInteger(bcpgIn).Value };
					break;
				case PublicKeyAlgorithmTag.ElGamalEncrypt:
				case PublicKeyAlgorithmTag.ElGamalGeneral:
                    data = new IBigInteger[]
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
			this.version = 3;
			this.keyId = keyId;
			this.algorithm = algorithm;
            this.data = (IBigInteger[])data.Clone();
		}

		public int Version
		{
			get { return version; }
		}

		public long KeyId
		{
			get { return keyId; }
		}

		public PublicKeyAlgorithmTag Algorithm
		{
			get { return algorithm; }
		}

        public IBigInteger[] GetEncSessionKey()
		{
            return (IBigInteger[])data.Clone();
		}

		public override void Encode(
			IBcpgOutputStream bcpgOut)
		{
		    using (MemoryStream bOut = new MemoryStream())
		    {
		        using (BcpgOutputStream pOut = new BcpgOutputStream(bOut))
		        {

		            pOut.WriteByte((byte) version);

		            pOut.WriteLong(keyId);

		            pOut.WriteByte((byte) algorithm);

		            for (int i = 0; i != data.Length; i++)
		            {
		                MPInteger.Encode(pOut, data[i]);
		            }

		            bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession, bOut.ToArray(), true);
		        }
		    }
		}
	}
}

using System;



namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class IssuerKeyId
        : SignatureSubpacket
    {
        protected static byte[] KeyIdToBytes(
            long    keyId)
        {
            byte[]    data = new byte[8];

            data[0] = (byte)(keyId >> 56);
            data[1] = (byte)(keyId >> 48);
            data[2] = (byte)(keyId >> 40);
            data[3] = (byte)(keyId >> 32);
            data[4] = (byte)(keyId >> 24);
            data[5] = (byte)(keyId >> 16);
            data[6] = (byte)(keyId >> 8);
            data[7] = (byte)keyId;

            return data;
        }

        public IssuerKeyId(
            bool    critical,
            byte[]     data)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, data)
        {
        }

        public IssuerKeyId(
            bool    critical,
            long       keyId)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, KeyIdToBytes(keyId))
        {
        }

        public long KeyId
        {
			get
			{
				long keyId = ((long)(Data[0] & 0xff) << 56)
					| ((long)(Data[1] & 0xff) << 48)
					| ((long)(Data[2] & 0xff) << 40)
					| ((long)(Data[3] & 0xff) << 32)
					| ((long)(Data[4] & 0xff) << 24)
					| ((long)(Data[5] & 0xff) << 16)
					| ((long)(Data[6] & 0xff) << 8)
					| ((long)Data[7] & 0xff);

				return keyId;
			}
        }
    }
}

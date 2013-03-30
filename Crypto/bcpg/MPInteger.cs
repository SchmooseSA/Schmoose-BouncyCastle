using System;
using System.IO;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>A multiple precision integer</remarks>
    public class MPInteger
        : BcpgObject
    {
        private readonly IBigInteger val;

        public MPInteger(
            BcpgInputStream bcpgIn)
        {
			if (bcpgIn == null)
				throw new ArgumentNullException("bcpgIn");

			int length = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            byte[] bytes = new byte[(length + 7) / 8];

            bcpgIn.ReadFully(bytes);

            this.val = new BigInteger(1, bytes);
        }

		public MPInteger(
            IBigInteger val)
        {
			if (val == null)
				throw new ArgumentNullException("val");
			if (val.SignValue < 0)
				throw new ArgumentException("Values must be positive", "val");

			this.val = val;
        }

        public IBigInteger Value
        {
            get { return val; }
        }

        public override void Encode(
            IBcpgOutputStream bcpgOut)
        {
			bcpgOut.WriteShort((short) val.BitLength);
			bcpgOut.Write(val.ToByteArrayUnsigned());
        }

		internal static void Encode(
			BcpgOutputStream	bcpgOut,
            IBigInteger val)
		{
			bcpgOut.WriteShort((short) val.BitLength);
			bcpgOut.Write(val.ToByteArrayUnsigned());
		}
    }
}

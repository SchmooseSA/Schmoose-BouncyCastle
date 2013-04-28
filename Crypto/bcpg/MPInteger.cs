using System;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>A multiple precision integer</remarks>
    public class MPInteger : BcpgObject
    {
        private readonly IBigInteger _val;

        public MPInteger(BcpgInputStream bcpgIn)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException("bcpgIn");

            var length = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            var bytes = new byte[(length + 7) / 8];

            bcpgIn.ReadFully(bytes);

            _val = new BigInteger(1, bytes);
        }

        public MPInteger(IBigInteger val)
        {
            if (val == null)
                throw new ArgumentNullException("val");
            if (val.SignValue < 0)
                throw new ArgumentException("Values must be positive", "val");

            _val = val;
        }

        public IBigInteger Value
        {
            get { return _val; }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            EncodeInteger(bcpgOut, _val);
        }

        internal static void EncodeInteger(IBcpgOutputStream bcpgOut, IBigInteger val)
        {
            bcpgOut.WriteShort((short)val.BitLength);
            bcpgOut.Write(val.ToByteArrayUnsigned());
        }
    }
}

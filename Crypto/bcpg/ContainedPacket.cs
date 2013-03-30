using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a PGP packet.</remarks>
    public abstract class ContainedPacket
        : Packet, IContainedPacket
	{
        public byte[] GetEncoded()
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                using (BcpgOutputStream pOut = new BcpgOutputStream(bOut))
                {

                    pOut.WritePacket(this);

                    return bOut.ToArray();
                }
            }
        }

		public abstract void Encode(IBcpgOutputStream bcpgOut);
    }
}

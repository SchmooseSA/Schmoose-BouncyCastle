using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a PGP packet.</remarks>
    public abstract class ContainedPacket : Packet, IContainedPacket
	{
        /// <summary>
        /// Gets the encoded version of this instance.
        /// </summary>
        /// <returns></returns>
        public byte[] GetEncoded()
        {
            using (var bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {
                    pOut.WritePacket(this);
                    return bOut.ToArray();
                }
            }
        }

        /// <summary>
        /// Encodes this instance to the given stream.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
		public abstract void Encode(IBcpgOutputStream bcpgOut);
    }
}

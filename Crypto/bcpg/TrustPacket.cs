using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <summary>Basic type for a trust packet.</summary>
    public class TrustPacket : ContainedPacket, ITrustPacket
	{
        private readonly byte[] _levelAndTrustAmount;

		public TrustPacket(BcpgInputStream bcpgIn)
        {
		    using (var bOut = new MemoryStream())
		    {
		        int ch;
		        while ((ch = bcpgIn.ReadByte()) >= 0)
		        {
		            bOut.WriteByte((byte) ch);
		        }

		        _levelAndTrustAmount = bOut.ToArray();
		    }
        }

		public TrustPacket(int trustCode)
        {
			this._levelAndTrustAmount = new[]{ (byte) trustCode };
        }

        /// <summary>
        /// Gets the level and trust amount.
        /// </summary>
        /// <returns></returns>
		public byte[] GetLevelAndTrustAmount()
		{
			return (byte[]) _levelAndTrustAmount.Clone();
		}

		public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.Trust, _levelAndTrustAmount, true);
        }
    }
}

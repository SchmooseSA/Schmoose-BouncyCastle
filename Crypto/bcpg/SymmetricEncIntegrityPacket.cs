namespace Org.BouncyCastle.Bcpg
{
	public class SymmetricEncIntegrityPacket : InputStreamPacket
	{
		internal readonly int Version;

		internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn)
			: base(bcpgIn)
        {
			this.Version = bcpgIn.ReadByte();
        }        
    }
}

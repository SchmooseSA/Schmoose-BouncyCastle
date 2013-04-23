namespace Org.BouncyCastle.Bcpg
{
    public class InputStreamPacket : Packet
    {
        private readonly BcpgInputStream _bcpgIn;

		public InputStreamPacket(BcpgInputStream bcpgIn)
        {
            _bcpgIn = bcpgIn;
        }

		/// <summary>Note: you can only read from this once...</summary>
		public BcpgInputStream GetInputStream()
        {
            return _bcpgIn;
        }
    }
}

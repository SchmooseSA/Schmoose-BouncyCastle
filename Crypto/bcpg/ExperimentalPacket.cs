namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for an experimental packet.</remarks>
    public class ExperimentalPacket : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private readonly PacketTag	_tag;
        private readonly byte[]		_contents;

		internal ExperimentalPacket(
            PacketTag		tag,
            BcpgInputStream	bcpgIn)
        {
            _tag = tag;
			_contents = bcpgIn.ReadAll();
        }

		public PacketTag Tag
        {
			get { return _tag; }
        }

		public byte[] GetContents()
        {
			return (byte[]) _contents.Clone();
        }

		public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(_tag, _contents, true);
        }
    }
}

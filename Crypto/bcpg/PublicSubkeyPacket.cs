using System;
namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public subkey</remarks>
    public class PublicSubkeyPacket : PublicKeyPacket
    {
        internal PublicSubkeyPacket(BcpgInputStream bcpgIn)
            : base(bcpgIn) { }

        /// <summary>Construct a version 4 public subkey packet.</summary>
        public PublicSubkeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgPublicKey key)
            : base(algorithm, time, key) { }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.PublicSubkey, GetEncodedContents(), true);
        }
    }
}

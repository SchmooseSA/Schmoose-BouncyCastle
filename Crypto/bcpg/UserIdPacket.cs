using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a user ID packet.
    */
    public class UserIdPacket : ContainedPacket
    {
        private readonly byte[] _idData;

        public UserIdPacket(BcpgInputStream bcpgIn)
        {
            _idData = bcpgIn.ReadAll();
        }

        public UserIdPacket(string id)
        {
            _idData = Encoding.UTF8.GetBytes(id);
        }

        public string GetId()
        {
            return Encoding.UTF8.GetString(_idData, 0, _idData.Length);
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.UserId, _idData, true);
        }
    }
}

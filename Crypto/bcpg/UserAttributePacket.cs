using System.IO;
using System.Linq;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a user attribute packet.
    */
    public class UserAttributePacket : ContainedPacket
    {
        private readonly IUserAttributeSubpacket[] _subpackets;

        public UserAttributePacket(BcpgInputStream bcpgIn)
        {
            var sIn = new UserAttributeSubpacketsParser(bcpgIn);
            UserAttributeSubpacket sub;

            var v = Platform.CreateArrayList<IUserAttributeSubpacket>();
            while ((sub = sIn.ReadPacket()) != null)
            {
                v.Add(sub);
            }
            _subpackets = v.ToArray();
        }

        public UserAttributePacket(IUserAttributeSubpacket[] subpackets)
        {
            _subpackets = subpackets;
        }

        public IUserAttributeSubpacket[] GetSubpackets()
        {
            return _subpackets;
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            using (var bOut = new MemoryStream())
            {

                for (var i = 0; i != _subpackets.Length; i++)
                {
                    _subpackets[i].Encode(bOut);
                }

                bcpgOut.WritePacket(PacketTag.UserAttribute, bOut.ToArray(), false);
            }
        }
    }
}

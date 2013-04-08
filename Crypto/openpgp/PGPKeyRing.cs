using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpKeyRing
        : PgpObject
    {
        internal PgpKeyRing() { }

        internal static TrustPacket ReadOptionalTrustPacket(
            BcpgInputStream bcpgInput)
        {
            return (bcpgInput.NextPacketTag() == PacketTag.Trust)
                ? (TrustPacket)bcpgInput.ReadPacket()
                : null;
        }

        internal static IList ReadSignaturesAndTrust(BcpgInputStream bcpgInput)
        {
            try
            {
                var sigList = Platform.CreateArrayList();

                while (bcpgInput.NextPacketTag() == PacketTag.Signature)
                {
                    var signaturePacket = (SignaturePacket)bcpgInput.ReadPacket();
                    var trustPacket = ReadOptionalTrustPacket(bcpgInput);

                    sigList.Add(new PgpSignature(signaturePacket, trustPacket));
                }

                return sigList;
            }
            catch (PgpException e)
            {
                throw new IOException("can't create signature object: " + e.Message, e);
            }
        }

        internal static void ReadUserIDs(BcpgInputStream bcpgInput, out IList ids, out IList idTrusts, out IList idSigs)
        {
            ids = Platform.CreateArrayList();
            idTrusts = Platform.CreateArrayList();
            idSigs = Platform.CreateArrayList();

            while (bcpgInput.NextPacketTag() == PacketTag.UserId
                || bcpgInput.NextPacketTag() == PacketTag.UserAttribute)
            {
                var obj = bcpgInput.ReadPacket();
                if (obj is UserIdPacket)
                {
                    var id = (UserIdPacket)obj;
                    ids.Add(id.GetId());
                }
                else
                {
                    var user = (UserAttributePacket)obj;
                    ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
                }

                idTrusts.Add(
                    ReadOptionalTrustPacket(bcpgInput));

                idSigs.Add(
                    ReadSignaturesAndTrust(bcpgInput));
            }
        }
    }
}

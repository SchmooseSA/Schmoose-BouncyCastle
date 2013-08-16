using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpKeyRing : PgpObject
    {
        internal PgpKeyRing() { }

        internal static ITrustPacket ReadOptionalTrustPacket(BcpgInputStream bcpgInput)
        {
            return (bcpgInput.NextPacketTag() == PacketTag.Trust)
                ? (ITrustPacket)bcpgInput.ReadPacket()
                : null;
        }

        internal static IList<IPgpSignature> ReadSignaturesAndTrust(BcpgInputStream bcpgInput)
        {
            try
            {
                var sigList = Platform.CreateArrayList<IPgpSignature>();

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

        internal static void ReadUserIDs(BcpgInputStream bcpgInput, out IList ids, out IList<ITrustPacket> idTrusts, out IList<IList<IPgpSignature>> idSigs)
        {
            ids = Platform.CreateArrayList();
            idTrusts = Platform.CreateArrayList<ITrustPacket>();
            idSigs = Platform.CreateArrayList<IList<IPgpSignature>>();

            while (bcpgInput.NextPacketTag() == PacketTag.UserId
                || bcpgInput.NextPacketTag() == PacketTag.UserAttribute)
            {
                var obj = bcpgInput.ReadPacket();
                var userIdPacket = obj as UserIdPacket;
                if (userIdPacket != null)
                {
                    ids.Add(userIdPacket.GetId());
                }
                else
                {
                    var user = (UserAttributePacket)obj;
                    ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
                }

                idTrusts.Add(ReadOptionalTrustPacket(bcpgInput));

                idSigs.Add(ReadSignaturesAndTrust(bcpgInput));
            }
        }
    }
}

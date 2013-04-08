using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A holder for a list of PGP encryption method packets.</remarks>
    public class PgpEncryptedDataList
        : PgpObject, IEnumerable<PgpEncryptedData>
    {
        private readonly IList<PgpEncryptedData> _list;
        private readonly InputStreamPacket _data;

        public PgpEncryptedDataList(
            BcpgInputStream bcpgInput)
        {
            var packets = new List<Packet>();
            while (bcpgInput.NextPacketTag() == PacketTag.PublicKeyEncryptedSession
                || bcpgInput.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                packets.Add(bcpgInput.ReadPacket());
            }

            _list = Platform.CreateArrayList<PgpEncryptedData>(packets.Count);
            _data = (InputStreamPacket)bcpgInput.ReadPacket();
            for (var i = 0; i != packets.Count; i++)
            {
                var symmetricPacket = packets[i] as SymmetricKeyEncSessionPacket;
                if (symmetricPacket != null)
                {
                    _list.Add(new PgpPbeEncryptedData(symmetricPacket, _data));
                }
                else
                {
                    _list.Add(new PgpPublicKeyEncryptedData((PublicKeyEncSessionPacket)packets[i], _data));
                }
            }
        }

        public PgpEncryptedData this[int index]
        {
            get { return _list[index]; }
        }

        [Obsolete("Use 'object[index]' syntax instead")]
        public object Get(int index)
        {
            return this[index];
        }

        [Obsolete("Use 'Count' property instead")]
        public int Size
        {
            get { return _list.Count; }
        }

        public int Count
        {
            get { return _list.Count; }
        }

        public bool IsEmpty
        {
            get { return _list.Count == 0; }
        }

        public IEnumerable GetEncryptedDataObjects()
        {
            return new EnumerableProxy(_list);
        }

        public IEnumerator<PgpEncryptedData> GetEnumerator()
        {
            return _list.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}

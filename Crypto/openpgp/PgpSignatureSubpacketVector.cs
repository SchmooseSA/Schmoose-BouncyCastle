using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Container for a list of signature subpackets.</remarks>
    public class PgpSignatureSubpacketVector : IPgpSignatureSubpacketVector
    {
        private readonly ISignatureSubpacket[] _packets;

        internal PgpSignatureSubpacketVector(ISignatureSubpacket[] packets)
        {
            _packets = packets;
        }

        public ISignatureSubpacket GetSubpacket(SignatureSubpacketTag type)
        {
            for (var i = 0; i != _packets.Length; i++)
            {
                if (_packets[i].SubpacketType == type)
                {
                    return _packets[i];
                }
            }

            return null;
        }

        /**
         * Return true if a particular subpacket type exists.
         *
         * @param type type to look for.
         * @return true if present, false otherwise.
         */
        public bool HasSubpacket(SignatureSubpacketTag type)
        {
            return GetSubpacket(type) != null;
        }

        /**
         * Return all signature subpackets of the passed in type.
         * @param type subpacket type code
         * @return an array of zero or more matching subpackets.
         */
        public ISignatureSubpacket[] GetSubpackets(SignatureSubpacketTag type)
        {
            return _packets.Where(t => t.SubpacketType == type).ToArray();
        }

        public INotationData[] GetNotationDataOccurences()
        {
            var notations = GetSubpackets(SignatureSubpacketTag.NotationData);
            var vals = new INotationData[notations.Length];

            for (var i = 0; i < notations.Length; i++)
            {
                vals[i] = (NotationData)notations[i];
            }

            return vals;
        }

        public long GetIssuerKeyId()
        {
            var p = GetSubpacket(SignatureSubpacketTag.IssuerKeyId);

            return p == null ? 0 : ((IssuerKeyId)p).KeyId;
        }

        public bool HasSignatureCreationTime()
        {
            return GetSubpacket(SignatureSubpacketTag.CreationTime) != null;
        }

        public DateTime GetSignatureCreationTime()
        {
            var p = GetSubpacket(SignatureSubpacketTag.CreationTime);

            if (p == null)
            {
                throw new PgpException("SignatureCreationTime not available");
            }

            return ((SignatureCreationTime)p).GetTime();
        }

        /// <summary>
        /// Return the number of seconds a signature is valid for after its creation date.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public long GetSignatureExpirationTime()
        {
            var p = GetSubpacket(SignatureSubpacketTag.ExpireTime);

            return p == null ? 0 : ((SignatureExpirationTime)p).Time;
        }

        /// <summary>
        /// Return the number of seconds a key is valid for after its creation date.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public long GetKeyExpirationTime()
        {
            var p = GetSubpacket(SignatureSubpacketTag.KeyExpireTime);
            return p == null ? 0 : ((KeyExpirationTime)p).Time;
        }

        public int[] GetPreferredHashAlgorithms()
        {
            var p = GetSubpacket(SignatureSubpacketTag.PreferredHashAlgorithms);
            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        public int[] GetPreferredSymmetricAlgorithms()
        {
            var p = GetSubpacket(SignatureSubpacketTag.PreferredSymmetricAlgorithms);
            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        public int[] GetPreferredCompressionAlgorithms()
        {
            var p = GetSubpacket(SignatureSubpacketTag.PreferredCompressionAlgorithms);
            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        public int GetKeyFlags()
        {
            var p = GetSubpacket(SignatureSubpacketTag.KeyFlags);
            return p == null ? 0 : ((KeyFlags)p).Flags;
        }

        public string GetSignerUserId()
        {
            var p = GetSubpacket(SignatureSubpacketTag.SignerUserId);

            return p == null ? null : ((SignerUserId)p).GetId();
        }

        public bool IsPrimaryUserId()
        {
            var primaryId = (PrimaryUserId)this.GetSubpacket(SignatureSubpacketTag.PrimaryUserId);

            return primaryId != null && primaryId.IsPrimaryUserId();
        }

        public SignatureSubpacketTag[] GetCriticalTags()
        {
            var list = new List<SignatureSubpacketTag>();
            for (var i = 0; i != _packets.Length; i++)
            {
                if (_packets[i].IsCritical())
                {
                    list.Add(_packets[i].SubpacketType);
                }
            }

            return list.ToArray();
        }

        [Obsolete("Use 'Count' property instead")]
        public int Size
        {
            get { return _packets.Length; }
        }

        /// <summary>Return the number of packets this vector contains.</summary>
        public int Count
        {
            get { return _packets.Length; }
        }

        public ISignatureSubpacket[] ToSubpacketArray()
        {
            return _packets;
        }
    }
}

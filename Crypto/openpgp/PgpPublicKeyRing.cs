using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// Class to hold a single master public key and its subkeys.
    /// <p>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the <c>PgpPublicKeyRingBundle</c> class.
    /// </p>
    /// </remarks>
    public class PgpPublicKeyRing : PgpKeyRing, IPgpPublicKeyRing
    {
        private readonly IList<IPgpPublicKey> _keys;

        public PgpPublicKeyRing(byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

        internal PgpPublicKeyRing(IList<IPgpPublicKey> pubKeys)
        {
            _keys = pubKeys;
        }

        public PgpPublicKeyRing(Stream inputStream)
        {
            _keys = Platform.CreateArrayList<IPgpPublicKey>();

            var bcpgInput = BcpgInputStream.Wrap(inputStream);

            var initialTag = bcpgInput.NextPacketTag();
            if (initialTag != PacketTag.PublicKey && initialTag != PacketTag.PublicSubkey)
            {
                throw new IOException("public key ring doesn't start with public key tag: "
                    + "tag 0x" + ((int)initialTag).ToString("X"));
            }

            var pubPk = (PublicKeyPacket)bcpgInput.ReadPacket();
            var trustPk = ReadOptionalTrustPacket(bcpgInput);

            // direct signatures and revocations
            var keySigs = ReadSignaturesAndTrust(bcpgInput);

            IList ids;
            IList<ITrustPacket> idTrusts;
            IList<IList<IPgpSignature>> idSigs;
            ReadUserIDs(bcpgInput, out ids, out idTrusts, out idSigs);

            _keys.Add(new PgpPublicKey(pubPk, trustPk, keySigs, ids, idTrusts, idSigs));


            // Read subkeys
            while (bcpgInput.NextPacketTag() == PacketTag.PublicSubkey)
            {
                _keys.Add(ReadSubkey(bcpgInput));
            }
        }

        /// <summary>Return the first public key in the ring.</summary>
        public IPgpPublicKey GetPublicKey()
        {
            return _keys[0];
        }

        /// <summary>Return the public key referred to by the passed in key ID if it is present.</summary>
        public IPgpPublicKey GetPublicKey(long keyId)
        {
            return _keys.FirstOrDefault(k => keyId == k.KeyId);
        }

        /// <summary>Allows enumeration of all the public keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpPublicKey</c> objects.</returns>
        public IEnumerable<IPgpPublicKey> GetPublicKeys()
        {
            return _keys;
        }

        public byte[] GetEncoded()
        {
            using (var bOut = new MemoryStream())
            {
                this.Encode(bOut);
                return bOut.ToArray();
            }
        }

        public void Encode(Stream outStr)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            foreach (PgpPublicKey k in _keys)
            {
                k.Encode(outStr);
            }
        }

        /// <summary>
        /// Returns a new key ring with the public key passed in either added or
        /// replacing an existing one.
        /// </summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be inserted.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c></returns>
        public static PgpPublicKeyRing InsertPublicKey(IPgpPublicKeyRing pubRing, IPgpPublicKey pubKey)
        {
            var keys = Platform.CreateArrayList(pubRing.GetPublicKeys());
            var found = false;
            var masterFound = false;

            for (var i = 0; i != keys.Count; i++)
            {
                var key = keys[i];

                if (key.KeyId == pubKey.KeyId)
                {
                    found = true;
                    keys[i] = pubKey;
                }
                if (key.IsMasterKey)
                {
                    masterFound = true;
                }
            }

            if (!found)
            {
                if (pubKey.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");

                    keys.Insert(0, pubKey);
                }
                else
                {
                    keys.Add(pubKey);
                }
            }

            return new PgpPublicKeyRing(keys);
        }

        /// <summary>Returns a new key ring with the public key passed in removed from the key ring.</summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c>, or null if pubKey is not found.</returns>
        public static PgpPublicKeyRing RemovePublicKey(PgpPublicKeyRing pubRing, PgpPublicKey pubKey)
        {
            var keys = Platform.CreateArrayList(pubRing._keys);
            var found = false;

            for (var i = 0; i < keys.Count; i++)
            {
                var key = (PgpPublicKey)keys[i];

                if (key.KeyId != pubKey.KeyId) 
                    continue;

                found = true;
                keys.RemoveAt(i);
            }

            return found ? new PgpPublicKeyRing(keys) : null;
        }

        internal static PgpPublicKey ReadSubkey(BcpgInputStream bcpgInput)
        {
            var pk = (PublicKeyPacket)bcpgInput.ReadPacket();
            var kTrust = ReadOptionalTrustPacket(bcpgInput);

            // PGP 8 actually leaves out the signature.
            var sigList = ReadSignaturesAndTrust(bcpgInput);

            return new PgpPublicKey(pk, kTrust, sigList);
        }
    }
}

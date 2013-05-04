using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// Class to hold a single master secret key and its subkeys.
    /// <p>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the <c>PgpSecretKeyRingBundle</c> class.
    /// </p>
    /// </remarks>
    public class PgpSecretKeyRing : PgpKeyRing, IPgpSecretKeyRing
    {
        private readonly IList<IPgpSecretKey> _keys;
        private readonly IList<IPgpPublicKey> _extraPubKeys;

        public PgpSecretKeyRing(IEnumerable keys)
            : this(keys != null ? keys.Cast<IPgpSecretKey>().ToList() : null, null)
        {
        }

        private PgpSecretKeyRing(IEnumerable<IPgpSecretKey> keys, IEnumerable<IPgpPublicKey> extraPubKeys)
        {
            _keys = keys != null ? keys.ToList() : Platform.CreateArrayList<IPgpSecretKey>();
            _extraPubKeys = extraPubKeys != null ? extraPubKeys.ToList() : Platform.CreateArrayList<IPgpPublicKey>();
        }

        public PgpSecretKeyRing(byte[] encoding)
            : this(new MemoryStream(encoding))
        {
        }

        public PgpSecretKeyRing(Stream inputStream)
        {
            _keys = Platform.CreateArrayList<IPgpSecretKey>();
            _extraPubKeys = Platform.CreateArrayList<IPgpPublicKey>();

            var bcpgInput = BcpgInputStream.Wrap(inputStream);

            var initialTag = bcpgInput.NextPacketTag();
            if (initialTag != PacketTag.SecretKey && initialTag != PacketTag.SecretSubkey)
            {
                throw new IOException("secret key ring doesn't start with secret key tag: "
                    + "tag 0x" + ((int)initialTag).ToString("X"));
            }

            var secret = (SecretKeyPacket)bcpgInput.ReadPacket();

            //
            // ignore GPG comment packets if found.
            //
            while (bcpgInput.NextPacketTag() == PacketTag.Experimental2)
            {
                bcpgInput.ReadPacket();
            }

            var trust = ReadOptionalTrustPacket(bcpgInput);

            // revocation and direct signatures
            var keySigs = ReadSignaturesAndTrust(bcpgInput);

            IList ids, idTrusts, idSigs;
            ReadUserIDs(bcpgInput, out ids, out idTrusts, out idSigs);

            _keys.Add(new PgpSecretKey(secret, new PgpPublicKey(secret.PublicKeyPacket, trust, keySigs, ids, idTrusts, idSigs)));


            // Read subkeys
            while (bcpgInput.NextPacketTag() == PacketTag.SecretSubkey
                || bcpgInput.NextPacketTag() == PacketTag.PublicSubkey)
            {
                if (bcpgInput.NextPacketTag() == PacketTag.SecretSubkey)
                {
                    var sub = (SecretSubkeyPacket)bcpgInput.ReadPacket();

                    //
                    // ignore GPG comment packets if found.
                    //
                    while (bcpgInput.NextPacketTag() == PacketTag.Experimental2)
                    {
                        bcpgInput.ReadPacket();
                    }

                    var subTrust = ReadOptionalTrustPacket(bcpgInput);
                    var sigList = ReadSignaturesAndTrust(bcpgInput);

                    _keys.Add(new PgpSecretKey(sub, new PgpPublicKey(sub.PublicKeyPacket, subTrust, sigList)));
                }
                else
                {
                    var sub = (PublicSubkeyPacket)bcpgInput.ReadPacket();

                    var subTrust = ReadOptionalTrustPacket(bcpgInput);
                    var sigList = ReadSignaturesAndTrust(bcpgInput);

                    _extraPubKeys.Add(new PgpPublicKey(sub, subTrust, sigList));
                }
            }
        }

        /// <summary>Return the public key for the master key.</summary>
        public IPgpPublicKey GetPublicKey()
        {
            return _keys[0].PublicKey;
        }

        /// <summary>Return the master private key.</summary>
        public IPgpSecretKey GetSecretKey()
        {
            return _keys[0];
        }

        /// <summary>Allows enumeration of the secret keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSecretKey</c> objects.</returns>
        public IEnumerable<IPgpSecretKey> GetSecretKeys()
        {
            return _keys;
        }

        public int SecretKeyCount
        {
            get { return _keys.Count; }
        }

        public IPgpSecretKey GetSecretKey(long keyId)
        {
            return _keys.FirstOrDefault(k => keyId == k.KeyId);
        }

        /// <summary>
        /// Return an iterator of the public keys in the secret key ring that
        /// have no matching private key. At the moment only personal certificate data
        /// appears in this fashion.
        /// </summary>
        /// <returns>An <c>IEnumerable</c> of unattached, or extra, public keys.</returns>
        public IEnumerable<IPgpPublicKey> GetExtraPublicKeys()
        {
            return _extraPubKeys;
        }

        public byte[] GetEncoded()
        {
            using (var bOut = new MemoryStream())
            {
                Encode(bOut);
                return bOut.ToArray();
            }
        }

        public void Encode(Stream outStr)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            foreach (var key in _keys)
            {
                key.Encode(outStr);
            }
            foreach (var extraPubKey in _extraPubKeys)
            {
                extraPubKey.Encode(outStr);
            }
        }

        /// <summary>
        /// Replace the public key set on the secret ring with the corresponding key off the public ring.
        /// </summary>
        /// <param name="secretRing">Secret ring to be changed.</param>
        /// <param name="publicRing">Public ring containing the new public key set.</param>
        public static PgpSecretKeyRing ReplacePublicKeys(PgpSecretKeyRing secretRing, PgpPublicKeyRing publicRing)
        {
            var newList = Platform.CreateArrayList(secretRing.SecretKeyCount);

            foreach (PgpSecretKey sk in secretRing.GetSecretKeys())
            {
                var pk = publicRing.GetPublicKey(sk.KeyId);
                newList.Add(PgpSecretKey.ReplacePublicKey(sk, pk));
            }

            return new PgpSecretKeyRing(newList);
        }

        /// <summary>
        /// Return a copy of the passed in secret key ring, with the master key and sub keys encrypted
        /// using a new password and the passed in algorithm.
        /// </summary>
        /// <param name="ring">The <c>PgpSecretKeyRing</c> to be copied.</param>
        /// <param name="oldPassPhrase">The current password for key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKeyRing CopyWithNewPassword(
            PgpSecretKeyRing ring,
            char[] oldPassPhrase,
            char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm,
            SecureRandom rand)
        {
            var newKeys = Platform.CreateArrayList<IPgpSecretKey>(ring.SecretKeyCount);
            foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
            {
                newKeys.Add(PgpSecretKey.CopyWithNewPassword(secretKey, oldPassPhrase, newPassPhrase, newEncAlgorithm, rand));
            }

            return new PgpSecretKeyRing(newKeys, ring._extraPubKeys);
        }

        /// <summary>
        /// Returns a new key ring with the secret key passed in either added or
        /// replacing an existing one with the same key ID.
        /// </summary>
        /// <param name="secRing">The secret key ring to be modified.</param>
        /// <param name="secKey">The secret key to be inserted.</param>
        /// <returns>A new <c>PgpSecretKeyRing</c></returns>
        public static PgpSecretKeyRing InsertSecretKey(IPgpSecretKeyRing secRing, IPgpSecretKey secKey)
        {
            var keys = Platform.CreateArrayList(secRing.GetSecretKeys());
            var found = false;
            var masterFound = false;

            for (var i = 0; i != keys.Count; i++)
            {
                var key = keys[i];

                if (key.KeyId == secKey.KeyId)
                {
                    found = true;
                    keys[i] = secKey;
                }
                if (key.IsMasterKey)
                {
                    masterFound = true;
                }
            }

            if (!found)
            {
                if (secKey.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");

                    keys.Insert(0, secKey);
                }
                else
                {
                    keys.Add(secKey);
                }
            }

            return new PgpSecretKeyRing(keys, secRing.GetExtraPublicKeys());
        }

        /// <summary>Returns a new key ring with the secret key passed in removed from the key ring.</summary>
        /// <param name="secRing">The secret key ring to be modified.</param>
        /// <param name="secKey">The secret key to be removed.</param>
        /// <returns>A new <c>PgpSecretKeyRing</c>, or null if secKey is not found.</returns>
        public static PgpSecretKeyRing RemoveSecretKey(PgpSecretKeyRing secRing, PgpSecretKey secKey)
        {
            var keys = Platform.CreateArrayList(secRing._keys);
            var found = false;

            for (var i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                if (key.KeyId != secKey.KeyId) 
                    continue;

                found = true;
                keys.RemoveAt(i);
            }

            return found ? new PgpSecretKeyRing(keys, secRing._extraPubKeys) : null;
        }
    }
}

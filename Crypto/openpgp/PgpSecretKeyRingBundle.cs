using System;
using System.Collections;
using System.Globalization;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
    /// If you want to read an entire secret key file in one hit this is the class for you.
    /// </remarks>
    public class PgpSecretKeyRingBundle
    {
        private readonly IDictionary _secretRings;
        private readonly IList _order;

        private PgpSecretKeyRingBundle(IDictionary secretRings, IList order)
        {
            _secretRings = secretRings;
            _order = order;
        }

        public PgpSecretKeyRingBundle(byte[] encoding)
            : this(new MemoryStream(encoding, false)) { }

        /// <summary>Build a PgpSecretKeyRingBundle from the passed in input stream.</summary>
        /// <param name="inputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpSecretKeyRing.</exception>
        public PgpSecretKeyRingBundle(Stream inputStream)
            : this(new PgpObjectFactory(inputStream).AllPgpObjects()) { }

        public PgpSecretKeyRingBundle(IEnumerable e)
        {
            _secretRings = Platform.CreateHashtable();
            _order = Platform.CreateArrayList();

            foreach (var obj in e)
            {
                var pgpSecret = obj as PgpSecretKeyRing;
                if (pgpSecret == null)
                {
                    throw new PgpException(obj.GetType().FullName + " found where PgpSecretKeyRing expected");
                }

                var key = pgpSecret.GetPublicKey().KeyId;
                _secretRings.Add(key, pgpSecret);
                _order.Add(key);
            }
        }

        [Obsolete("Use 'Count' property instead")]
        public int Size
        {
            get { return _order.Count; }
        }

        /// <summary>Return the number of rings in this collection.</summary>
        public int Count
        {
            get { return _order.Count; }
        }

        /// <summary>Allow enumeration of the secret key rings making up this collection.</summary>
        public IEnumerable GetKeyRings()
        {
            return new EnumerableProxy(_secretRings.Values);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable GetKeyRings(string userId)
        {
            return GetKeyRings(userId, false, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable GetKeyRings(string userId, bool matchPartial)
        {
            return GetKeyRings(userId, matchPartial, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="ignoreCase">If true, case is ignored in user ID comparisons.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable GetKeyRings(string userId, bool matchPartial, bool ignoreCase)
        {
            var rings = Platform.CreateArrayList();
            if (ignoreCase)
            {
                userId = Platform.StringToLower(userId);
            }

            foreach (PgpSecretKeyRing secRing in GetKeyRings())
            {
                foreach (string nextUserId in secRing.GetSecretKey().UserIds)
                {
                    var next = nextUserId;
                    if (ignoreCase)
                    {
                        next = Platform.StringToLower(next);
                    }

                    if (matchPartial)
                    {
                        if (next.IndexOf(userId, System.StringComparison.Ordinal) > -1)
                        {
                            rings.Add(secRing);
                        }
                    }
                    else
                    {
                        if (next.Equals(userId))
                        {
                            rings.Add(secRing);
                        }
                    }
                }
            }

            return new EnumerableProxy(rings);
        }

        /// <summary>Return the PGP secret key associated with the given key id.</summary>
        /// <param name="keyId">The ID of the secret key to return.</param>
        public IPgpSecretKey GetSecretKey(long keyId)
        {
            foreach (PgpSecretKeyRing secRing in GetKeyRings())
            {
                var sec = secRing.GetSecretKey(keyId);

                if (sec != null)
                {
                    return sec;
                }
            }

            return null;
        }

        /// <summary>Return the secret key ring which contains the key referred to by keyId</summary>
        /// <param name="keyId">The ID of the secret key</param>
        public PgpSecretKeyRing GetSecretKeyRing(long keyId)
        {
            var id = keyId;

            if (_secretRings.Contains(id))
            {
                return (PgpSecretKeyRing)_secretRings[id];
            }

            foreach (PgpSecretKeyRing secretRing in GetKeyRings())
            {
                var secret = secretRing.GetSecretKey(keyId);

                if (secret != null)
                {
                    return secretRing;
                }
            }

            return null;
        }

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="keyId">key ID to look for.</param>
        public bool Contains(long keyId)
        {
            return GetSecretKey(keyId) != null;
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
            var bcpgOut = BcpgOutputStream.Wrap(outStr);

            foreach (long key in _order)
            {
                var pub = (PgpSecretKeyRing)_secretRings[key];

                pub.Encode(bcpgOut);
            }
        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle and
        /// the passed in secret key ring.
        /// </summary>
        /// <param name="bundle">The <c>PgpSecretKeyRingBundle</c> the key ring is to be added to.</param>
        /// <param name="secretKeyRing">The key ring to be added.</param>
        /// <returns>A new <c>PgpSecretKeyRingBundle</c> merging the current one with the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is already present.</exception>
        public static PgpSecretKeyRingBundle AddSecretKeyRing(PgpSecretKeyRingBundle bundle, PgpSecretKeyRing secretKeyRing)
        {
            var key = secretKeyRing.GetPublicKey().KeyId;

            if (bundle._secretRings.Contains(key))
            {
                throw new ArgumentException("Collection already contains a key with a keyId for the passed in ring.");
            }

            var newSecretRings = Platform.CreateHashtable(bundle._secretRings);
            var newOrder = Platform.CreateArrayList(bundle._order);

            newSecretRings[key] = secretKeyRing;
            newOrder.Add(key);

            return new PgpSecretKeyRingBundle(newSecretRings, newOrder);
        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle with
        /// the passed in secret key ring removed.
        /// </summary>
        /// <param name="bundle">The <c>PgpSecretKeyRingBundle</c> the key ring is to be removed from.</param>
        /// <param name="secretKeyRing">The key ring to be removed.</param>
        /// <returns>A new <c>PgpSecretKeyRingBundle</c> not containing the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is not present.</exception>
        public static PgpSecretKeyRingBundle RemoveSecretKeyRing(PgpSecretKeyRingBundle bundle, PgpSecretKeyRing secretKeyRing)
        {
            var key = secretKeyRing.GetPublicKey().KeyId;

            if (!bundle._secretRings.Contains(key))
            {
                throw new ArgumentException("Collection does not contain a key with a keyId for the passed in ring.");
            }

            var newSecretRings = Platform.CreateHashtable(bundle._secretRings);
            var newOrder = Platform.CreateArrayList(bundle._order);

            newSecretRings.Remove(key);
            newOrder.Remove(key);

            return new PgpSecretKeyRingBundle(newSecretRings, newOrder);
        }
    }
}

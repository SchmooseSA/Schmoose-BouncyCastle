using System;
using System.Collections;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to handle a PGP public key object.</remarks>
    public class PgpPublicKey : IPgpPublicKey
    {
        private static readonly int[] _masterKeyCertificationTypes = new[]
		{
			PgpSignature.PositiveCertification,
			PgpSignature.CasualCertification,
			PgpSignature.NoCertification,
			PgpSignature.DefaultCertification
		};

        private byte[] _fingerprint;

        internal PublicKeyPacket PublicPk;
        internal TrustPacket TrustPk;
        internal IList KeySigs = Platform.CreateArrayList();
        internal IList Ids = Platform.CreateArrayList();
        internal IList IdTrusts = Platform.CreateArrayList();
        internal IList IdSigs = Platform.CreateArrayList();
        internal IList SubSigs;

        private void Init()
        {
            var key = PublicPk.Key;

            if (PublicPk.Version <= 3)
            {
                var rK = (RsaPublicBcpgKey)key;

                KeyId = rK.Modulus.LongValue;

                try
                {
                    var digest = DigestUtilities.GetDigest("MD5");

                    var bytes = rK.Modulus.ToByteArrayUnsigned();
                    digest.BlockUpdate(bytes, 0, bytes.Length);

                    bytes = rK.PublicExponent.ToByteArrayUnsigned();
                    digest.BlockUpdate(bytes, 0, bytes.Length);

                    _fingerprint = DigestUtilities.DoFinal(digest);
                }
                //catch (NoSuchAlgorithmException)
                catch (Exception e)
                {
                    throw new IOException("can't find MD5", e);
                }

                BitStrength = rK.Modulus.BitLength;
            }
            else
            {
                var kBytes = PublicPk.GetEncodedContents();

                try
                {
                    var digest = DigestUtilities.GetDigest("SHA1");

                    digest.Update(0x99);
                    digest.Update((byte)(kBytes.Length >> 8));
                    digest.Update((byte)kBytes.Length);
                    digest.BlockUpdate(kBytes, 0, kBytes.Length);
                    _fingerprint = DigestUtilities.DoFinal(digest);
                }
                catch (Exception e)
                {
                    throw new IOException("can't find SHA1", e);
                }

                this.KeyId = (long)(((ulong)_fingerprint[_fingerprint.Length - 8] << 56)
                    | ((ulong)_fingerprint[_fingerprint.Length - 7] << 48)
                    | ((ulong)_fingerprint[_fingerprint.Length - 6] << 40)
                    | ((ulong)_fingerprint[_fingerprint.Length - 5] << 32)
                    | ((ulong)_fingerprint[_fingerprint.Length - 4] << 24)
                    | ((ulong)_fingerprint[_fingerprint.Length - 3] << 16)
                    | ((ulong)_fingerprint[_fingerprint.Length - 2] << 8)
                    | (ulong)_fingerprint[_fingerprint.Length - 1]);

                if (key is RsaPublicBcpgKey)
                {
                    BitStrength = ((RsaPublicBcpgKey)key).Modulus.BitLength;
                }
                else if (key is DsaPublicBcpgKey)
                {
                    BitStrength = ((DsaPublicBcpgKey)key).P.BitLength;
                }
                else if (key is ElGamalPublicBcpgKey)
                {
                    BitStrength = ((ElGamalPublicBcpgKey)key).P.BitLength;
                }
                else if (key is EcPublicBcpgKey)
                {
                    BitStrength = ((EcPublicBcpgKey) key).BitStrength;
                }
            }
        }

        /// <summary>
        /// Create a PgpPublicKey from the passed in lightweight one.
        /// </summary>
        /// <remarks>
        /// Note: the time passed in affects the value of the key's keyId, so you probably only want
        /// to do this once for a lightweight key, or make sure you keep track of the time you used.
        /// </remarks>
        /// <param name="algorithm">Asymmetric algorithm type representing the public key.</param>
        /// <param name="pubKey">Actual public key to associate.</param>
        /// <param name="time">Date of creation.</param>
        /// <exception cref="ArgumentException">If <c>pubKey</c> is not public.</exception>
        /// <exception cref="PgpException">On key creation problem.</exception>
        public PgpPublicKey(
            PublicKeyAlgorithmTag algorithm,
            IAsymmetricKeyParameter pubKey,
            DateTime time)
        {
            if (pubKey.IsPrivate)
                throw new ArgumentException("Expected a public key", "pubKey");

            IBcpgKey bcpgKey;
            if (pubKey is RsaKeyParameters)
            {
                var rK = (RsaKeyParameters)pubKey;

                bcpgKey = new RsaPublicBcpgKey(rK.Modulus, rK.Exponent);
            }
            else if (pubKey is DsaPublicKeyParameters)
            {
                var dK = (DsaPublicKeyParameters)pubKey;
                var dP = dK.Parameters;

                bcpgKey = new DsaPublicBcpgKey(dP.P, dP.Q, dP.G, dK.Y);
            }
            else if (pubKey is ElGamalPublicKeyParameters)
            {
                var eK = (ElGamalPublicKeyParameters)pubKey;
                var eS = eK.Parameters;

                bcpgKey = new ElGamalPublicBcpgKey(eS.P, eS.G, eK.Y);
            }
            else
            {
                throw new PgpException("unknown key class");
            }

            this.PublicPk = new PublicKeyPacket(algorithm, time, bcpgKey);
            this.Ids = Platform.CreateArrayList();
            this.IdSigs = Platform.CreateArrayList();

            try
            {
                Init();
            }
            catch (IOException e)
            {
                throw new PgpException("exception calculating keyId", e);
            }
        }

        /// <summary>Constructor for a sub-key.</summary>
        internal PgpPublicKey(PublicKeyPacket publicPk, TrustPacket trustPk, IList sigs)
        {
            this.PublicPk = publicPk;
            this.TrustPk = trustPk;
            this.SubSigs = sigs;

            Init();
        }

        internal PgpPublicKey(PgpPublicKey key, TrustPacket trust, IList subSigs)
        {
            this.PublicPk = key.PublicPk;
            this.TrustPk = trust;
            this.SubSigs = subSigs;

            _fingerprint = key.GetFingerprint();
            KeyId = key.KeyId;
            BitStrength = key.BitStrength;
        }

        /// <summary>Copy constructor.</summary>
        /// <param name="pubKey">The public key to copy.</param>
        internal PgpPublicKey(PgpPublicKey pubKey)
        {
            this.PublicPk = pubKey.PublicPk;

            this.KeySigs = Platform.CreateArrayList(pubKey.KeySigs);
            this.Ids = Platform.CreateArrayList(pubKey.Ids);
            this.IdTrusts = Platform.CreateArrayList(pubKey.IdTrusts);
            this.IdSigs = Platform.CreateArrayList(pubKey.IdSigs.Count);
            for (var i = 0; i != pubKey.IdSigs.Count; i++)
            {
                this.IdSigs.Add(Platform.CreateArrayList((IList)pubKey.IdSigs[i]));
            }

            if (pubKey.SubSigs != null)
            {
                this.SubSigs = Platform.CreateArrayList(pubKey.SubSigs.Count);
                for (var i = 0; i != pubKey.SubSigs.Count; i++)
                {
                    this.SubSigs.Add(pubKey.SubSigs[i]);
                }
            }

            _fingerprint = pubKey.GetFingerprint();
            KeyId = pubKey.KeyId;
            BitStrength = pubKey.BitStrength;
        }

        internal PgpPublicKey(PublicKeyPacket publicPk, TrustPacket trustPk, IList keySigs, IList ids, IList idTrusts, IList idSigs)
        {
            this.PublicPk = publicPk;
            this.TrustPk = trustPk;
            this.KeySigs = keySigs;
            this.Ids = ids;
            this.IdTrusts = idTrusts;
            this.IdSigs = idSigs;

            Init();
        }

        internal PgpPublicKey(PublicKeyPacket publicPk, IList ids, IList idSigs)
        {
            this.PublicPk = publicPk;
            this.Ids = ids;
            this.IdSigs = idSigs;
            Init();
        }

        /// <summary>The version of this key.</summary>
        public int Version
        {
            get { return PublicPk.Version; }
        }

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime
        {
            get { return PublicPk.GetTime(); }
        }

        /// <summary>The number of valid days from creation time - zero means no expiry.</summary>
        public int ValidDays
        {
            get
            {
                if (PublicPk.Version > 3)
                {
                    return (int)(GetValidSeconds() / (24 * 60 * 60));
                }

                return PublicPk.ValidDays;
            }
        }

        public IPublicKeyPacket PublicKeyPacket
        {
            get { return PublicPk; }
        }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public byte[] GetTrustData()
        {
            return TrustPk == null ? null : TrustPk.GetLevelAndTrustAmount();
        }

        /// <summary>The number of valid seconds from creation time - zero means no expiry.</summary>
        public long GetValidSeconds()
        {
            if (PublicPk.Version > 3)
            {
                if (IsMasterKey)
                {
                    for (var i = 0; i != _masterKeyCertificationTypes.Length; i++)
                    {
                        var seconds = GetExpirationTimeFromSig(true, _masterKeyCertificationTypes[i]);

                        if (seconds >= 0)
                        {
                            return seconds;
                        }
                    }
                }
                else
                {
                    var seconds = GetExpirationTimeFromSig(false, PgpSignature.SubkeyBinding);

                    if (seconds >= 0)
                    {
                        return seconds;
                    }
                }

                return 0;
            }

            return (long)PublicPk.ValidDays * 24 * 60 * 60;
        }

        private long GetExpirationTimeFromSig(
            bool selfSigned,
            int signatureType)
        {
            foreach (PgpSignature sig in GetSignaturesOfType(signatureType))
            {
                if (selfSigned && sig.KeyId != KeyId)
                    continue;

                var hashed = sig.GetHashedSubPackets();
                return hashed != null ? hashed.GetKeyExpirationTime() : 0;
            }

            return -1;
        }

        /// <summary>The keyId associated with the public key.</summary>
        public long KeyId { get; private set; }

        /// <summary>The fingerprint of the key</summary>
        public byte[] GetFingerprint()
        {
            return (byte[])_fingerprint.Clone();
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for encryption.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for encryption.
        /// </returns>
        public bool IsEncryptionKey
        {
            get
            {
                switch (PublicPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey
        {
            get { return SubSigs == null; }
        }

        /// <summary>The algorithm code associated with the public key.</summary>
        public PublicKeyAlgorithmTag Algorithm
        {
            get { return PublicPk.Algorithm; }
        }

        /// <summary>The strength of the key in bits.</summary>
        public int BitStrength { get; private set; }

        /// <summary>The public key contained in the object.</summary>
        /// <returns>A lightweight public key.</returns>
        /// <exception cref="PgpException">If the key algorithm is not recognised.</exception>
        public IAsymmetricKeyParameter GetKey()
        {
            try
            {
                switch (PublicPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                        var rsaK = (RsaPublicBcpgKey)PublicPk.Key;
                        return new RsaKeyParameters(false, rsaK.Modulus, rsaK.PublicExponent);
                    case PublicKeyAlgorithmTag.Dsa:
                        var dsaK = (DsaPublicBcpgKey)PublicPk.Key;
                        return new DsaPublicKeyParameters(dsaK.Y, new DsaParameters(dsaK.P, dsaK.Q, dsaK.G));
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        var elK = (ElGamalPublicBcpgKey)PublicPk.Key;
                        return new ElGamalPublicKeyParameters(elK.Y, new ElGamalParameters(elK.P, elK.G));
                    default:
                        throw new PgpException("unknown public key algorithm encountered");
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception constructing public key", e);
            }
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable GetUserIds()
        {
            IList temp = Platform.CreateArrayList();

            foreach (object o in Ids)
            {
                if (o is string)
                {
                    temp.Add(o);
                }
            }

            return new EnumerableProxy(temp);
        }

        public string[] UserIdentities
        {
            get
            {
                return Ids.OfType<string>().ToArray();
            }
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable GetUserAttributes()
        {
            IList temp = Platform.CreateArrayList();

            foreach (object o in Ids)
            {
                if (o is PgpUserAttributeSubpacketVector)
                {
                    temp.Add(o);
                }
            }

            return new EnumerableProxy(temp);
        }

        /// <summary>Allows enumeration of any signatures associated with the passed in id.</summary>
        /// <param name="id">The ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable GetSignaturesForId(
            string id)
        {
            if (id == null)
                throw new ArgumentNullException("id");

            for (int i = 0; i != Ids.Count; i++)
            {
                if (id.Equals(Ids[i]))
                {
                    return new EnumerableProxy((IList)IdSigs[i]);
                }
            }

            return null;
        }

        /// <summary>Allows enumeration of signatures associated with the passed in user attributes.</summary>
        /// <param name="userAttributes">The vector of user attributes to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable GetSignaturesForUserAttribute(
            IPgpUserAttributeSubpacketVector userAttributes)
        {
            for (int i = 0; i != Ids.Count; i++)
            {
                if (userAttributes.Equals(Ids[i]))
                {
                    return new EnumerableProxy((IList)IdSigs[i]);
                }
            }

            return null;
        }

        /// <summary>Allows enumeration of signatures of the passed in type that are on this key.</summary>
        /// <param name="signatureType">The type of the signature to be returned.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable GetSignaturesOfType(
            int signatureType)
        {
            IList temp = Platform.CreateArrayList();

            foreach (PgpSignature sig in GetSignatures())
            {
                if (sig.SignatureType == signatureType)
                {
                    temp.Add(sig);
                }
            }

            return new EnumerableProxy(temp);
        }

        /// <summary>Allows enumeration of all signatures/certifications associated with this key.</summary>
        /// <returns>An <c>IEnumerable</c> with all signatures/certifications.</returns>
        public IEnumerable GetSignatures()
        {
            IList sigs;
            if (SubSigs != null)
            {
                sigs = SubSigs;
            }
            else
            {
                sigs = Platform.CreateArrayList(KeySigs);

                foreach (ICollection extraSigs in IdSigs)
                {
                    CollectionUtilities.AddRange(sigs, extraSigs);
                }
            }

            return new EnumerableProxy(sigs);
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

            bcpgOut.WritePacket(PublicPk);
            if (TrustPk != null)
            {
                bcpgOut.WritePacket(TrustPk);
            }

            if (SubSigs == null) // not a sub-key
            {
                foreach (PgpSignature keySig in KeySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (var i = 0; i != Ids.Count; i++)
                {
                    if (Ids[i] is string)
                    {
                        var id = (string)Ids[i];

                        bcpgOut.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        var v = (PgpUserAttributeSubpacketVector)Ids[i];
                        bcpgOut.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (IdTrusts[i] != null)
                    {
                        bcpgOut.WritePacket((ContainedPacket)IdTrusts[i]);
                    }

                    foreach (PgpSignature sig in (IList)IdSigs[i])
                    {
                        sig.Encode(bcpgOut);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in SubSigs)
                {
                    subSig.Encode(bcpgOut);
                }
            }
        }

        /// <summary>
        /// Check whether this (sub)key has a revocation signature on it.
        /// </summary>
        /// <returns>
        /// True, if this (sub)key has been revoked.
        /// </returns>
        public bool IsRevoked()
        {
            var ns = 0;
            var revoked = false;
            if (IsMasterKey)	// Master key
            {
                while (!revoked && (ns < KeySigs.Count))
                {
                    if (((PgpSignature)KeySigs[ns++]).SignatureType == PgpSignature.KeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            else	// Sub-key
            {
                while (!revoked && (ns < SubSigs.Count))
                {
                    if (((PgpSignature)SubSigs[ns++]).SignatureType == PgpSignature.SubkeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            return revoked;
        }

        /// <summary>
        /// Add a certification for an id to the given public key.
        /// </summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="id">The ID the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>
        /// The re-certified key.
        /// </returns>
        public static PgpPublicKey AddCertification(IPgpPublicKey key, string id, PgpSignature certification)
        {
            return AddCert(key, id, certification);
        }

        /// <summary>
        /// Add a certification for the given UserAttributeSubpackets to the given public key.
        /// </summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="userAttributes">The attributes the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>
        /// The re-certified key.
        /// </returns>
        public static PgpPublicKey AddCertification(
            IPgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes,
            PgpSignature certification)
        {
            return AddCert(key, userAttributes, certification);
        }

        private static PgpPublicKey AddCert(IPgpPublicKey key, object id, PgpSignature certification)
        {
            var returnKey = new PgpPublicKey((PgpPublicKey)key);
            IList sigList = null;

            for (var i = 0; i != returnKey.Ids.Count; i++)
            {
                if (id.Equals(returnKey.Ids[i]))
                {
                    sigList = (IList)returnKey.IdSigs[i];
                }
            }

            if (sigList != null)
            {
                sigList.Add(certification);
            }
            else
            {
                sigList = Platform.CreateArrayList();
                sigList.Add(certification);
                returnKey.Ids.Add(id);
                returnKey.IdTrusts.Add(null);
                returnKey.IdSigs.Add(sigList);
            }

            return returnKey;
        }

        /// <summary>
        /// Remove any certifications associated with a user attribute subpacket on a key.
        /// </summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The attributes to be removed.</param>
        /// <returns>
        /// The re-certified key, or null if the user attribute subpacket was not found on the key.
        /// </returns>
        public static IPgpPublicKey RemoveCertification(IPgpPublicKey key, PgpUserAttributeSubpacketVector userAttributes)
        {
            return RemoveCert(key, userAttributes);
        }

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that is to be removed.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static IPgpPublicKey RemoveCertification(
            IPgpPublicKey key,
            string id)
        {
            return RemoveCert(key, id);
        }

        private static IPgpPublicKey RemoveCert(IPgpPublicKey key, object id)
        {
            var returnKey = new PgpPublicKey((PgpPublicKey)key);
            var found = false;

            for (var i = 0; i < returnKey.Ids.Count; i++)
            {
                if (!id.Equals(returnKey.Ids[i]))
                    continue;

                found = true;
                returnKey.Ids.RemoveAt(i);
                returnKey.IdTrusts.RemoveAt(i);
                returnKey.IdSigs.RemoveAt(i);
            }

            return found ? returnKey : null;
        }

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that the certfication is to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(IPgpPublicKey key, string id, PgpSignature certification)
        {
            return RemoveCert(key, id, certification);
        }

        /// <summary>Remove a certification associated with a given user attributes on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The user attributes that the certfication is to be removed from.</param>
        /// <param name="certification">The certification to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(IPgpPublicKey key, PgpUserAttributeSubpacketVector userAttributes, PgpSignature certification)
        {
            return RemoveCert(key, userAttributes, certification);
        }

        private static PgpPublicKey RemoveCert(IPgpPublicKey key, object id, PgpSignature certification)
        {
            var returnKey = new PgpPublicKey((PgpPublicKey)key);
            var found = false;

            for (var i = 0; i < returnKey.Ids.Count; i++)
            {
                if (!id.Equals(returnKey.Ids[i]))
                    continue;

                var certs = (IList)returnKey.IdSigs[i];
                found = certs.Contains(certification);
                if (found)
                {
                    certs.Remove(certification);
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Add a revocation or some other key certification to a key.</summary>
        /// <param name="key">The key the revocation is to be added to.</param>
        /// <param name="certification">The key signature to be added.</param>
        /// <returns>The new changed public key object.</returns>
        public static PgpPublicKey AddCertification(IPgpPublicKey key, PgpSignature certification)
        {
            if (key.IsMasterKey)
            {
                if (certification.SignatureType == PgpSignature.SubkeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for master key revocation.");
                }
            }
            else
            {
                if (certification.SignatureType == PgpSignature.KeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for sub-key revocation.");
                }
            }

            var returnKey = new PgpPublicKey((PgpPublicKey)key);
            if (returnKey.SubSigs != null)
            {
                returnKey.SubSigs.Add(certification);
            }
            else
            {
                returnKey.KeySigs.Add(certification);
            }

            return returnKey;
        }

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey key, PgpSignature certification)
        {
            var returnKey = new PgpPublicKey(key);
            var sigs = returnKey.SubSigs ?? returnKey.KeySigs;

            //			bool found = sigs.Remove(certification);
            var pos = sigs.IndexOf(certification);
            var found = pos >= 0;

            if (found)
            {
                sigs.RemoveAt(pos);
            }
            else
            {
                foreach (string id in key.GetUserIds())
                {
                    foreach (var sig in key.GetSignaturesForId(id))
                    {
                        // TODO Is this the right type of equality test?
                        if (certification != sig)
                            continue;

                        found = true;
                        returnKey = PgpPublicKey.RemoveCertification(returnKey, id, certification);
                    }
                }

                if (!found)
                {
                    foreach (PgpUserAttributeSubpacketVector id in key.GetUserAttributes())
                    {
                        foreach (var sig in key.GetSignaturesForUserAttribute(id))
                        {
                            // TODO Is this the right type of equality test?
                            if (certification != sig) continue;
                            // found = true;
                            returnKey = PgpPublicKey.RemoveCertification(returnKey, id, certification);
                        }
                    }
                }
            }

            return returnKey;
        }
    }
}

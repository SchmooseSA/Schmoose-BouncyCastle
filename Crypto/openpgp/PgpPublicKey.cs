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

        private IPublicKeyPacket _publicPk;
        private readonly ITrustPacket _trustPk;
        private readonly IList _keySigs = Platform.CreateArrayList();
        private readonly IList _ids = Platform.CreateArrayList();
        private readonly IList _idTrusts = Platform.CreateArrayList();
        private readonly IList _idSigs = Platform.CreateArrayList();
        private readonly IList _subSigs;
        
        private void Init()
        {
            var key = _publicPk.Key;

            if (_publicPk.Version <= 3)
            {
                var rK = (RsaPublicBcpgKey)key;

                _fingerprint = BuildFingerprintMd5(_publicPk);
                this.KeyId = rK.Modulus.LongValue;
                this.BitStrength = rK.Modulus.BitLength;
            }
            else
            {
                _fingerprint = BuildFingerprintSha1(_publicPk);
                this.KeyId = (long)(((ulong)_fingerprint[_fingerprint.Length - 8] << 56)
                    | ((ulong)_fingerprint[_fingerprint.Length - 7] << 48)
                    | ((ulong)_fingerprint[_fingerprint.Length - 6] << 40)
                    | ((ulong)_fingerprint[_fingerprint.Length - 5] << 32)
                    | ((ulong)_fingerprint[_fingerprint.Length - 4] << 24)
                    | ((ulong)_fingerprint[_fingerprint.Length - 3] << 16)
                    | ((ulong)_fingerprint[_fingerprint.Length - 2] << 8)
                    |  (ulong)_fingerprint[_fingerprint.Length - 1]);

                this.BitStrength = key.BitStrength;
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
        public PgpPublicKey(PublicKeyAlgorithmTag algorithm, IAsymmetricKeyParameter pubKey, DateTime time)
        {
            if (pubKey.IsPrivate)
                throw new ArgumentException("Expected a public key", "pubKey");

            IBcpgPublicKey bcpgKey;

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
            else if (pubKey is ECDHPublicKeyParameters)
            {
                var ecdh = (ECDHPublicKeyParameters) pubKey;
                 
                bcpgKey = new EcdhPublicBcpgKey(ecdh.Q, ecdh.PublicKeyParamSet, ecdh.HashAlgorithm, ecdh.SymmetricKeyAlgorithm);
            }
            else if (pubKey is ECPublicKeyParameters)
            {
                var ecdsa = (ECPublicKeyParameters)pubKey;
                bcpgKey = new EcdsaPublicBcpgKey(ecdsa.Q, ecdsa.PublicKeyParamSet);
            }
            else
            {
                throw new PgpException("unknown key class");
            }

            _publicPk = new PublicKeyPacket(algorithm, time, bcpgKey);
            _ids = Platform.CreateArrayList();
            _idSigs = Platform.CreateArrayList();

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
        internal PgpPublicKey(IPublicKeyPacket publicPk, TrustPacket trustPk, IList sigs)
        {
            this._publicPk = publicPk;
            this._trustPk = trustPk;
            this._subSigs = sigs;

            Init();
        }

        internal PgpPublicKey(PgpPublicKey key, TrustPacket trust, IList subSigs)
        {
            this._publicPk = key._publicPk;
            this._trustPk = trust;
            this._subSigs = subSigs;

            _fingerprint = key.GetFingerprint();
            KeyId = key.KeyId;
            BitStrength = key.BitStrength;
        }

        /// <summary>Copy constructor.</summary>
        /// <param name="pubKey">The public key to copy.</param>
        internal PgpPublicKey(PgpPublicKey pubKey)
        {
            this._publicPk = pubKey._publicPk;

            this._keySigs = Platform.CreateArrayList(pubKey._keySigs);
            this._ids = Platform.CreateArrayList(pubKey._ids);
            this._idTrusts = Platform.CreateArrayList(pubKey._idTrusts);
            this._idSigs = Platform.CreateArrayList(pubKey._idSigs.Count);
            for (var i = 0; i != pubKey._idSigs.Count; i++)
            {
                this._idSigs.Add(Platform.CreateArrayList((IList)pubKey._idSigs[i]));
            }

            if (pubKey._subSigs != null)
            {
                this._subSigs = Platform.CreateArrayList(pubKey._subSigs.Count);
                for (var i = 0; i != pubKey._subSigs.Count; i++)
                {
                    this._subSigs.Add(pubKey._subSigs[i]);
                }
            }

            _fingerprint = pubKey.GetFingerprint();
            KeyId = pubKey.KeyId;
            BitStrength = pubKey.BitStrength;
        }

        internal PgpPublicKey(IPublicKeyPacket publicPk, TrustPacket trustPk, IList keySigs, IList ids, IList idTrusts, IList idSigs)
        {
            this._publicPk = publicPk;
            this._trustPk = trustPk;
            this._keySigs = keySigs;
            this._ids = ids;
            this._idTrusts = idTrusts;
            this._idSigs = idSigs;

            Init();
        }

        internal PgpPublicKey(IPublicKeyPacket publicPk, IList ids, IList idSigs)
        {
            this._publicPk = publicPk;
            this._ids = ids;
            this._idSigs = idSigs;
            Init();
        }

        /// <summary>The version of this key.</summary>
        public int Version
        {
            get { return _publicPk.Version; }
        }

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime
        {
            get { return _publicPk.GetTime(); }
        }

        /// <summary>The number of valid days from creation time - zero means no expiry.</summary>
        public int ValidDays
        {
            get
            {
                if (_publicPk.Version > 3)
                {
                    return (int)(GetValidSeconds() / (24 * 60 * 60));
                }

                return _publicPk.ValidDays;
            }
        }

        public IPublicKeyPacket PublicKeyPacket
        {
            get { return _publicPk; }
            internal set { _publicPk = value; }
        }

        public ITrustPacket TrustPaket 
        {
            get { return _trustPk; }
        }

        public IList KeySigs 
        {
            get { return _keySigs; }
        }
        public IList Ids
        {
            get { return _ids; }
        }

        public IList IdTrusts
        {
            get { return _idTrusts; }
        }

        public IList IdSigs
        {
            get { return _idSigs; }
        }

        public IList SubSigs
        {
            get { return _subSigs; }
        }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public byte[] GetTrustData()
        {
            return _trustPk == null ? null : _trustPk.GetLevelAndTrustAmount();
        }

        /// <summary>The number of valid seconds from creation time - zero means no expiry.</summary>
        public long GetValidSeconds()
        {
            if (_publicPk.Version > 3)
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

            return (long)_publicPk.ValidDays * 24 * 60 * 60;
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
                switch (_publicPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.Ecdh:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey
        {
            get { return _subSigs == null; }
        }

        /// <summary>The algorithm code associated with the public key.</summary>
        public PublicKeyAlgorithmTag Algorithm
        {
            get { return _publicPk.Algorithm; }
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
                switch (_publicPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                        var rsaK = (RsaPublicBcpgKey)_publicPk.Key;
                        return new RsaKeyParameters(false, rsaK.Modulus, rsaK.PublicExponent);
                    case PublicKeyAlgorithmTag.Dsa:
                        var dsaK = (DsaPublicBcpgKey)_publicPk.Key;
                        return new DsaPublicKeyParameters(dsaK.Y, new DsaParameters(dsaK.P, dsaK.Q, dsaK.G));
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        var elK = (ElGamalPublicBcpgKey)_publicPk.Key;
                        return new ElGamalPublicKeyParameters(elK.Y, new ElGamalParameters(elK.P, elK.G));
                    case PublicKeyAlgorithmTag.Ecdsa:
                        var ecdsaK = (EcdsaPublicBcpgKey) _publicPk.Key;
                        return new ECPublicKeyParameters(_publicPk.Algorithm.ToString(), ecdsaK.Point, ecdsaK.Oid);
                    case PublicKeyAlgorithmTag.Ecdh:
                        var edhK = (EcdhPublicBcpgKey) _publicPk.Key;
                        return new ECDHPublicKeyParameters(edhK.Point, edhK.Oid, edhK.HashAlgorithm, edhK.SymmetricKeyAlgorithm);
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

            foreach (object o in _ids)
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
                return _ids.OfType<string>().ToArray();
            }
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable GetUserAttributes()
        {
            IList temp = Platform.CreateArrayList();

            foreach (object o in _ids)
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

            for (int i = 0; i != _ids.Count; i++)
            {
                if (id.Equals(_ids[i]))
                {
                    return new EnumerableProxy((IList)_idSigs[i]);
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
            for (int i = 0; i != _ids.Count; i++)
            {
                if (userAttributes.Equals(_ids[i]))
                {
                    return new EnumerableProxy((IList)_idSigs[i]);
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
            if (_subSigs != null)
            {
                sigs = _subSigs;
            }
            else
            {
                sigs = Platform.CreateArrayList(_keySigs);

                foreach (ICollection extraSigs in _idSigs)
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

            bcpgOut.WritePacket(_publicPk);
            if (_trustPk != null)
            {
                bcpgOut.WritePacket(_trustPk);
            }

            if (_subSigs == null) // not a sub-key
            {
                foreach (PgpSignature keySig in _keySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (var i = 0; i != _ids.Count; i++)
                {
                    var id = this._ids[i] as string;
                    if (id != null)
                    {
                        bcpgOut.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        var v = (PgpUserAttributeSubpacketVector)this._ids[i];
                        bcpgOut.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (this._idTrusts[i] != null)
                    {
                        bcpgOut.WritePacket((ContainedPacket)this._idTrusts[i]);
                    }

                    foreach (PgpSignature sig in (IList)this._idSigs[i])
                    {
                        sig.Encode(bcpgOut);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in _subSigs)
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
                while (!revoked && (ns < _keySigs.Count))
                {
                    if (((PgpSignature)_keySigs[ns++]).SignatureType == PgpSignature.KeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            else	// Sub-key
            {
                while (!revoked && (ns < _subSigs.Count))
                {
                    if (((PgpSignature)_subSigs[ns++]).SignatureType == PgpSignature.SubkeyRevocation)
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

            for (var i = 0; i != returnKey._ids.Count; i++)
            {
                if (id.Equals(returnKey._ids[i]))
                {
                    sigList = (IList)returnKey._idSigs[i];
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
                returnKey._ids.Add(id);
                returnKey._idTrusts.Add(null);
                returnKey._idSigs.Add(sigList);
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

            for (var i = 0; i < returnKey._ids.Count; i++)
            {
                if (!id.Equals(returnKey._ids[i]))
                    continue;

                found = true;
                returnKey._ids.RemoveAt(i);
                returnKey._idTrusts.RemoveAt(i);
                returnKey._idSigs.RemoveAt(i);
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

            for (var i = 0; i < returnKey._ids.Count; i++)
            {
                if (!id.Equals(returnKey._ids[i]))
                    continue;

                var certs = (IList)returnKey._idSigs[i];
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

        public static byte[] BuildFingerprint(IPublicKeyPacket publicPk)
        {
            return publicPk.Version <= 3 ? BuildFingerprintMd5(publicPk) : BuildFingerprintSha1(publicPk);
        }

        private static byte[] BuildFingerprintMd5(IPublicKeyPacket publicPk)
        {
            var rK = (RsaPublicBcpgKey)publicPk.Key;

            try
            {
                var digest = DigestUtilities.GetDigest("MD5");

                var bytes = rK.Modulus.ToByteArrayUnsigned();
                digest.BlockUpdate(bytes, 0, bytes.Length);

                bytes = rK.PublicExponent.ToByteArrayUnsigned();
                digest.BlockUpdate(bytes, 0, bytes.Length);

                return DigestUtilities.DoFinal(digest);
            }
            catch (Exception e)
            {
                throw new IOException("can't find MD5", e);
            }
        }

        private static byte[] BuildFingerprintSha1(IPublicKeyPacket publicPk)
        {
            var kBytes = publicPk.GetEncodedContents();

            try
            {
                var digest = DigestUtilities.GetDigest("SHA1");

                digest.Update(0x99);
                digest.Update((byte)(kBytes.Length >> 8));
                digest.Update((byte)kBytes.Length);
                digest.BlockUpdate(kBytes, 0, kBytes.Length);
                return DigestUtilities.DoFinal(digest);
            }
            catch (Exception e)
            {
                throw new IOException("can't find SHA1", e);
            }
        }
    }
}

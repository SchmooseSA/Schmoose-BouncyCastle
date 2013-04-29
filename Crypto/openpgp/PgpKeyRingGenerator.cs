using System;
using System.Collections;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// Generator for a PGP master and subkey ring.
    /// This class will generate both the secret and public key rings
    /// </remarks>
    public class PgpKeyRingGenerator
    {
        private readonly IList _keys = Platform.CreateArrayList();
        private readonly SymmetricKeyAlgorithmTag _encAlgorithm;
        private readonly HashAlgorithmTag _hashAlgorithm;
        private readonly char[] _passPhrase;
        private readonly bool _useSha1;
        private readonly PgpKeyPair _masterKey;
        private readonly PgpSignatureSubpacketVector _hashedPacketVector;
        private readonly PgpSignatureSubpacketVector _unhashedPacketVector;
        private readonly ISecureRandom _rand;

        /// <summary>
        /// Create a new key ring generator using old style checksumming. It is recommended to use
        /// SHA1 checksumming where possible.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int certificationLevel,
            PgpKeyPair masterKey,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            ISecureRandom rand)
            : this(certificationLevel, masterKey, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)
        {
        }

        public PgpKeyRingGenerator(
            int certificationLevel,
            PgpKeyPair masterKey,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            ISecureRandom rand)
            : this(certificationLevel, masterKey, id, encAlgorithm, HashAlgorithmTag.Sha1, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">Checksum the secret keys with SHA1 rather than the older 16 bit checksum.</param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int certificationLevel,
            PgpKeyPair masterKey,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            ISecureRandom rand)
        {
            _masterKey = masterKey;
            _encAlgorithm = encAlgorithm;
            _passPhrase = passPhrase;
            _useSha1 = useSha1;
            _hashedPacketVector = hashedPackets;
            _unhashedPacketVector = unhashedPackets;
            _rand = rand;
            _hashAlgorithm = hashAlgorithm;

            _keys.Add(new PgpSecretKey(certificationLevel, masterKey, id, encAlgorithm, hashAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand));
        }

        /// <summary>
        /// Adds the sub key.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        public void AddSubKey(PgpKeyPair keyPair)
        {
            this.AddSubKey(keyPair, _hashAlgorithm);
        }

        /// <summary>
        /// Add a subkey to the key ring to be generated with default certification.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        public void AddSubKey(PgpKeyPair keyPair, HashAlgorithmTag hashAlgorithm)
        {
            this.AddSubKey(keyPair, _hashedPacketVector, _unhashedPacketVector, hashAlgorithm);
        }

        /// <summary>
        /// Adds the sub key.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        /// <param name="hashedPackets">The hashed packets.</param>
        /// <param name="unhashedPackets">The unhashed packets.</param>
        public void AddSubKey(
            PgpKeyPair keyPair, 
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
        {
            this.AddSubKey(keyPair, hashedPackets, unhashedPackets, _hashAlgorithm);
        }

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification.
        /// </summary>
        /// <param name="keyPair">Public/private key pair.</param>
        /// <param name="hashedPackets">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedPackets">Unhashed packets values to be included in certification.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">exception adding subkey: </exception>
        /// <exception cref="PgpException"></exception>
        public void AddSubKey(
            PgpKeyPair keyPair, 
            PgpSignatureSubpacketVector hashedPackets, 
            PgpSignatureSubpacketVector unhashedPackets, 
            HashAlgorithmTag hashAlgorithm)
        {
            try
            {
                var sGen = new PgpSignatureGenerator(_masterKey.PublicKey.Algorithm, hashAlgorithm);

                //
                // Generate the certification
                //
                sGen.InitSign(PgpSignature.SubkeyBinding, _masterKey.PrivateKey);

                sGen.SetHashedSubpackets(hashedPackets);
                sGen.SetUnhashedSubpackets(unhashedPackets);

                var subSigs = Platform.CreateArrayList();
                subSigs.Add(sGen.GenerateCertification(_masterKey.PublicKey, keyPair.PublicKey));

                _keys.Add(new PgpSecretKey(keyPair.PrivateKey, new PgpPublicKey(keyPair.PublicKey, null, subSigs), _encAlgorithm, _passPhrase, _useSha1, _rand));
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception adding subkey: ", e);
            }
        }

        /// <summary>Return the secret key ring.</summary>
        public PgpSecretKeyRing GenerateSecretKeyRing()
        {
            return new PgpSecretKeyRing(_keys);
        }

        /// <summary>Return the public key ring that corresponds to the secret key ring.</summary>
        public PgpPublicKeyRing GeneratePublicKeyRing()
        {
            var pubKeys = Platform.CreateArrayList();

            var enumerator = _keys.GetEnumerator();
            enumerator.MoveNext();

            var pgpSecretKey = (PgpSecretKey)enumerator.Current;
            pubKeys.Add(pgpSecretKey.PublicKey);

            while (enumerator.MoveNext())
            {
                pgpSecretKey = (PgpSecretKey)enumerator.Current;

                var k = new PgpPublicKey((PgpPublicKey)pgpSecretKey.PublicKey);
                k.PublicPk = new PublicSubkeyPacket(k.Algorithm, k.CreationTime, k.PublicPk.Key);

                pubKeys.Add(k);
            }

            return new PgpPublicKeyRing(pubKeys);
        }
    }
}

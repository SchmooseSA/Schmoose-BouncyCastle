using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpPublicKey
    {
        /// <summary>The version of this key.</summary>
        int Version { get; }

        /// <summary>The creation time of this key.</summary>
        DateTime CreationTime { get; }

        /// <summary>The number of valid days from creation time - zero means no expiry.</summary>
        int ValidDays { get; }

        /// <summary>The keyId associated with the public key.</summary>
        long KeyId { get; }

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
        bool IsEncryptionKey { get; }

        /// <summary>True, if this is a master key.</summary>
        bool IsMasterKey { get; }

        /// <summary>The algorithm code associated with the public key.</summary>
        PublicKeyAlgorithmTag Algorithm { get; }

        /// <summary>
        /// Gets the user identities.
        /// </summary>
        /// <value>
        /// The user identities.
        /// </value>
        string[] UserIdentities { get; }


        /// <summary>
        /// The public key packet
        /// </summary>
        /// <value>
        /// The public key packet.
        /// </value>
        IPublicKeyPacket PublicKeyPacket { get; }

        /// <summary>The strength of the key in bits.</summary>
        int BitStrength { get; }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        byte[] GetTrustData();

        /// <summary>The number of valid seconds from creation time - zero means no expiry.</summary>
        long GetValidSeconds();

        /// <summary>The fingerprint of the key</summary>
        byte[] GetFingerprint();

        /// <summary>The public key contained in the object.</summary>
        /// <returns>A lightweight public key.</returns>
        /// <exception cref="PgpException">If the key algorithm is not recognised.</exception>
        IAsymmetricKeyParameter GetKey();

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        IEnumerable GetUserIds();

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        IEnumerable GetUserAttributes();

        /// <summary>Allows enumeration of any signatures associated with the passed in id.</summary>
        /// <param name="id">The ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        IEnumerable GetSignaturesForId(
            string id);

        /// <summary>Allows enumeration of signatures associated with the passed in user attributes.</summary>
        /// <param name="userAttributes">The vector of user attributes to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        IEnumerable GetSignaturesForUserAttribute(
            IPgpUserAttributeSubpacketVector userAttributes);

        /// <summary>Allows enumeration of signatures of the passed in type that are on this key.</summary>
        /// <param name="signatureType">The type of the signature to be returned.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        IEnumerable GetSignaturesOfType(
            int signatureType);

        /// <summary>Allows enumeration of all signatures/certifications associated with this key.</summary>
        /// <returns>An <c>IEnumerable</c> with all signatures/certifications.</returns>
        IEnumerable GetSignatures();

        byte[] GetEncoded();

        void Encode(
            Stream outStr);

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <returns>True, if this (sub)key has been revoked.</returns>
        bool IsRevoked();
    }
}
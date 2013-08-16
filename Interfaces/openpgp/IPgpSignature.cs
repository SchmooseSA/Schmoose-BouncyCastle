using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpSignature
    {
        /// <summary>
        /// The OpenPGP version number for this signature.
        /// </summary>
        /// <value>
        /// The version.
        /// </value>
        int Version { get; }

        /// <summary>
        /// The key algorithm associated with this signature.
        /// </summary>
        /// <value>
        /// The key algorithm.
        /// </value>
        PublicKeyAlgorithmTag KeyAlgorithm { get; }

        /// <summary>
        /// The hash algorithm associated with this signature.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        HashAlgorithmTag HashAlgorithm { get; }

        /// <summary>
        /// Gets the type of the signature.
        /// </summary>
        /// <value>
        /// The type of the signature.
        /// </value>
        int SignatureType { get; }

        /// <summary>
        /// The ID of the key that created the signature.
        /// </summary>
        /// <value>
        /// The key id.
        /// </value>
        long KeyId { get; }

        /// <summary>
        /// The creation time of this signature.
        /// </summary>
        /// <value>
        /// The creation time.
        /// </value>
        DateTime CreationTime { get; }

        /// <summary>
        /// Return true if the signature has either hashed or unhashed subpackets.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance has subpackets; otherwise, <c>false</c>.
        /// </value>
        bool HasSubpackets { get; }

        /// <summary>
        /// Inits the verification process.
        /// </summary>
        /// <param name="pubKey">The pub key.</param>
        /// <exception cref="PgpException">invalid key.</exception>
        void InitVerify(IPgpPublicKey pubKey);

        /// <summary>
        /// Updates the instance with the given data.
        /// </summary>
        /// <param name="b">The b.</param>
        void Update(byte b);

        /// <summary>
        /// Updates the instance with the given data.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        void Update(params byte[] bytes);

        /// <summary>
        /// Updates the instance with the given data.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <param name="off">The off.</param>
        /// <param name="length">The length.</param>
        void Update(byte[] bytes, int off, int length);

        /// <summary>
        /// Verifies this instance.
        /// </summary>
        /// <returns></returns>
        bool Verify();

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in user attributes.
        /// </summary>
        /// <param name="userAttributes">User attributes the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        bool VerifyCertification(IPgpUserAttributeSubpacketVector userAttributes, IPgpPublicKey key);

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in ID.
        /// </summary>
        /// <param name="id">ID the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        bool VerifyCertification(string id, IPgpPublicKey key);

        /// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are verifying against.</param>
        /// <param name="pubKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        bool VerifyCertification(IPgpPublicKey masterKey, IPgpPublicKey pubKey);

        /// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        bool VerifyCertification(IPgpPublicKey pubKey);

        /// <summary>
        /// Gets the creation time.
        /// </summary>
        /// <returns></returns>
        [Obsolete("Use 'CreationTime' property instead")]
        DateTime GetCreationTime();

        /// <summary>
        /// Gets the signature trailer.
        /// </summary>
        /// <returns></returns>
        byte[] GetSignatureTrailer();

        /// <summary>
        /// Gets the hashed sub packets.
        /// </summary>
        /// <returns></returns>
        IPgpSignatureSubpacketVector GetHashedSubPackets();

        /// <summary>
        /// Gets the unhashed sub packets.
        /// </summary>
        /// <returns></returns>
        IPgpSignatureSubpacketVector GetUnhashedSubPackets();

        /// <summary>
        /// Gets the signature.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="PgpException">exception encoding DSA sig.</exception>
        byte[] GetSignature();

        byte[] GetEncoded();

        void Encode(Stream outStream);
    }
}
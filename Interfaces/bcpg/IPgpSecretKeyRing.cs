using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpSecretKeyRing
    {
        /// <summary>Return the public key for the master key.</summary>
        IPgpPublicKey GetPublicKey();

        /// <summary>Return the master private key.</summary>
        IPgpSecretKey GetSecretKey();

        /// <summary>Allows enumeration of the secret keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSecretKey</c> objects.</returns>
        IEnumerable<IPgpSecretKey> GetSecretKeys();

        /// <summary>
        /// Gets the secret key count.
        /// </summary>
        /// <value>
        /// The secret key count.
        /// </value>
        int SecretKeyCount { get; }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        /// <param name="keyId">The key id.</param>
        /// <returns></returns>
        IPgpSecretKey GetSecretKey(long keyId);

        /// <summary>
        /// Return an iterator of the public keys in the secret key ring that
        /// have no matching private key. At the moment only personal certificate data
        /// appears in this fashion.
        /// </summary>
        /// <returns>An <c>IEnumerable</c> of unattached, or extra, public keys.</returns>
        IEnumerable<IPgpPublicKey> GetExtraPublicKeys();

        byte[] GetEncoded();

        void Encode(Stream outStr);
    }
}
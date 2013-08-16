using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpPublicKeyRing
    {
        /// <summary>Return the first public key in the ring.</summary>
        IPgpPublicKey GetPublicKey();

        /// <summary>Return the public key referred to by the passed in key ID if it is present.</summary>
        IPgpPublicKey GetPublicKey(long keyId);

        /// <summary>Allows enumeration of all the public keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpPublicKey</c> objects.</returns>
        IEnumerable<IPgpPublicKey> GetPublicKeys();

        byte[] GetEncoded();

        void Encode(Stream outStr);
    }
}
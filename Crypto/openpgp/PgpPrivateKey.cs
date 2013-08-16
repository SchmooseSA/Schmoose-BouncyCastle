using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to contain a private key for use with other OpenPGP objects.</remarks>
    public class PgpPrivateKey : IPgpPrivateKey
    {
        private readonly long _keyId;
        private readonly IAsymmetricKeyParameter _privateKey;

        /// <summary>
        /// Create a PgpPrivateKey from a regular private key and the ID of its
        /// associated public key.
        /// </summary>
        /// <param name="privateKey">Private key to use.</param>
        /// <param name="keyId">ID of the corresponding public key.</param>
        public PgpPrivateKey(IAsymmetricKeyParameter privateKey, long keyId)
        {
            if (!privateKey.IsPrivate)
                throw new ArgumentException(@"Expected a private key", "privateKey");

            _privateKey = privateKey;
            _keyId = keyId;
        }

        /// <summary>The keyId associated with the contained private key.</summary>
        public long KeyId
        {
            get { return _keyId; }
        }

        /// <summary>The contained private key.</summary>
        public IAsymmetricKeyParameter Key
        {
            get { return _privateKey; }
        }
    }
}

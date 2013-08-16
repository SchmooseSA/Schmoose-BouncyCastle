namespace Org.BouncyCastle.Crypto.Parameters
{
    public class IesWithCipherParameters : IesParameters
    {
        private readonly int _cipherKeySize;

        /**
         * @param derivation the derivation parameter for the KDF function.
         * @param encoding the encoding parameter for the KDF function.
         * @param macKeySize the size of the MAC key (in bits).
         * @param cipherKeySize the size of the associated Cipher key (in bits).
         */
        public IesWithCipherParameters(byte[] derivation, byte[] encoding, int macKeySize, int cipherKeySize)
            : base(derivation, encoding, macKeySize)
        {
            _cipherKeySize = cipherKeySize;
        }

        public int CipherKeySize
        {
            get { return _cipherKeySize; }
        }
    }

}

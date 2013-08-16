namespace Org.BouncyCastle.Crypto.Parameters
{
    /**
     * parameters for using an integrated cipher in stream mode.
     */
    public class IesParameters : ICipherParameters
    {
        /**
         * @param derivation the derivation parameter for the KDF function.
         * @param encoding the encoding parameter for the KDF function.
         * @param macKeySize the size of the MAC key (in bits).
         */
        public IesParameters(byte[] derivation, byte[] encoding, int macKeySize)
        {
            this.Derivation = derivation;
            this.Encoding = encoding;
            this.MacKeySize = macKeySize;
        }

        public byte[] Derivation { get; private set; }

        public byte[] Encoding { get; private set; }

        public int MacKeySize { get; private set; }
    }

}

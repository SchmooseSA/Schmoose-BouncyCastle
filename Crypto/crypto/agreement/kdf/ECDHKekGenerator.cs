using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /**
    * X9.63 based key derivation function for ECDH CMS.
    */
    public class EcdhKekGenerator : IDerivationFunction
    {
        private readonly IDerivationFunction _kdf;

        private DerObjectIdentifier _algorithm;
        private int _keySize;
        private byte[] _z;

        public EcdhKekGenerator(IDigest digest)
        {
            _kdf = new Kdf2BytesGenerator(digest);
        }

        public void Init(IDerivationParameters param)
        {
            var parameters = (DHKdfParameters)param;

            this._algorithm = parameters.Algorithm;
            this._keySize = parameters.KeySize;
            this._z = parameters.GetZ(); // TODO Clone?
        }

        public IDigest Digest
        {
            get { return _kdf.Digest; }
        }

        public int GenerateBytes(byte[] outBytes, int outOff, int len)
        {
            // TODO Create an ASN.1 class for this (RFC3278)
            // ECC-CMS-SharedInfo
            var s = new DerSequence(
                new AlgorithmIdentifier(_algorithm, DerNull.Instance),
                new DerTaggedObject(true, 2, new DerOctetString(IntegerToBytes(_keySize))));

            _kdf.Init(new KdfParameters(_z, s.GetDerEncoded()));

            return _kdf.GenerateBytes(outBytes, outOff, len);
        }

        private static byte[] IntegerToBytes(int keySize)
        {
            var val = new byte[4];

            val[0] = (byte)(keySize >> 24);
            val[1] = (byte)(keySize >> 16);
            val[2] = (byte)(keySize >> 8);
            val[3] = (byte)keySize;

            return val;
        }
    }
}

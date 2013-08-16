using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    public class ECMqvWithKdfBasicAgreement : ECMqvBasicAgreement
    {
        private readonly string _algorithm;
        private readonly IDerivationFunction _kdf;

        public ECMqvWithKdfBasicAgreement(string algorithm, IDerivationFunction kdf)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (kdf == null)
                throw new ArgumentNullException("kdf");

            _algorithm = algorithm;
            _kdf = kdf;
        }

        public override IBigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            // Note that the ec.KeyAgreement class in JCE only uses kdf in one
            // of the engineGenerateSecret methods.

            var result = base.CalculateAgreement(pubKey);

            var keySize = GeneratorUtilities.GetDefaultKeySize(_algorithm);

            var dhKdfParams = new DHKdfParameters(
                new DerObjectIdentifier(_algorithm),
                keySize,
                BigIntToBytes(result));

            _kdf.Init(dhKdfParams);

            var keyBytes = new byte[keySize / 8];
            _kdf.GenerateBytes(keyBytes, 0, keyBytes.Length);

            return new BigInteger(1, keyBytes);
        }

        private byte[] BigIntToBytes(IBigInteger r)
        {
            var byteLength = X9IntegerConverter.GetByteLength(PrivParams.StaticPrivateKey.Parameters.G.X);
            return X9IntegerConverter.IntegerToBytes(r, byteLength);
        }
    }
}

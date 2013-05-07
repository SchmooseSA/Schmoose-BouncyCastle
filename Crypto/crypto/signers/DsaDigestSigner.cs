using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class DsaDigestSigner : ISigner
    {
        private readonly IDigest _digest;
        private readonly IDsa _dsaSigner;
        private bool _forSigning;

        public DsaDigestSigner(IDsa signer, IDigest digest)
        {
            _digest = digest;
            _dsaSigner = signer;
        }

        /// <summary>
        /// Returns the name of the algorithm the signer implements.
        /// </summary>        
        public string AlgorithmName
        {
            get { return _digest.AlgorithmName + "with" + _dsaSigner.AlgorithmName; }
        }

        /// <summary>
        /// Initialise the signer for signing or verification.
        /// </summary>
        /// <param name="forSigning"></param>
        /// <param name="parameters"></param>        
        /// <exception cref="InvalidKeyException">
        /// Signing Requires Private Key.
        /// or
        /// Verification Requires Public Key.
        /// </exception>
        public void Init(bool forSigning, ICipherParameters parameters)
        {
            _forSigning = forSigning;

            IAsymmetricKeyParameter k;

            var parametersWithRandom = parameters as ParametersWithRandom;
            if (parametersWithRandom != null)
            {
                k = (AsymmetricKeyParameter)parametersWithRandom.Parameters;
            }
            else
            {
                k = (AsymmetricKeyParameter)parameters;
            }

            if (forSigning && !k.IsPrivate)
                throw new InvalidKeyException("Signing Requires Private Key.");

            if (!forSigning && k.IsPrivate)
                throw new InvalidKeyException("Verification Requires Public Key.");

            this.Reset();

            _dsaSigner.Init(forSigning, parameters);
        }

        /// <summary>
        /// update the internal digest with the byte b
        /// </summary>
        /// <param name="input"></param>
        public void Update(byte input)
        {
            _digest.Update(input);
        }

        /// <summary>
        /// update the internal digest with the byte array in
        /// </summary>
        /// <param name="input"></param>
        /// <param name="inOff"></param>
        /// <param name="length"></param>        
        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            _digest.BlockUpdate(input, inOff, length);
        }

        /// <summary>
        /// Generate a signature for the message we've been loaded with using
        /// the key we were initialised with.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="System.InvalidOperationException">DSADigestSigner not initialised for signature generation.</exception>
        public byte[] GenerateSignature()
        {
            if (!_forSigning)
                throw new InvalidOperationException("DSADigestSigner not initialised for signature generation.");

            var hash = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(hash, 0);

            var sig = _dsaSigner.GenerateSignature(hash);
            return DerEncode(sig[0], sig[1]);
        }

        /// <summary>
        /// return true if the internal state represents the signature described
        /// in the passed in array.
        /// </summary>
        /// <param name="signature"></param>
        /// <returns>
        /// true if the internal state represents the signature described in the passed in array.
        /// </returns>        
        /// <exception cref="System.InvalidOperationException">DSADigestSigner not initialised for verification</exception>
        public bool VerifySignature(byte[] signature)
        {
            if (_forSigning)
                throw new InvalidOperationException("DSADigestSigner not initialised for verification");

            var hash = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(hash, 0);

            try
            {
                var sig = DerDecode(signature);
                return _dsaSigner.VerifySignature(hash, sig[0], sig[1]);
            }
            catch (IOException)
            {
                return false;
            }
        }

        /// <summary>Reset the internal state</summary>
        public void Reset()
        {
            _digest.Reset();
        }

        private static byte[] DerEncode(IBigInteger r, IBigInteger s)
        {
            return new DerSequence(new DerInteger(r), new DerInteger(s)).GetDerEncoded();
        }

        private static IBigInteger[] DerDecode(byte[] encoding)
        {
            var s = (Asn1Sequence)Asn1Object.FromByteArray(encoding);
            return new[]
			{
				((DerInteger) s[0]).Value,
				((DerInteger) s[1]).Value
			};
        }
    }
}

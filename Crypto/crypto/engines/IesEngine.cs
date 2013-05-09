using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
    * support class for constructing intergrated encryption ciphers
    * for doing basic message exchanges on top of key agreement ciphers
    */
    public class IesEngine
    {
        private readonly IBasicAgreement _agree;
        private readonly IDerivationFunction _kdf;
        private readonly IMac _mac;
        private readonly BufferedBlockCipher _cipher;
        private readonly byte[] _macBuf;

        private ICipherParameters _privParam;
        private ICipherParameters _pubParam;
        private IesParameters _param;

        public IesEngine(IBasicAgreement agree)
        {
            _agree = agree;
        }

        /**
        * set up for use with stream mode, where the key derivation function
        * is used to provide a stream of bytes to xor with the message.
        *
        * @param agree the key agreement used as the basis for the encryption
        * @param kdf the key derivation function used for byte generation
        * @param mac the message authentication code generator for the message
        */
        public IesEngine(IBasicAgreement agree, IDerivationFunction kdf, IMac mac)
        {
            _agree = agree;
            _kdf = kdf;
            _mac = mac;
            _macBuf = new byte[mac.GetMacSize()];
            //            this.cipher = null;
        }

        /**
        * set up for use in conjunction with a block cipher to handle the
        * message.
        *
        * @param agree the key agreement used as the basis for the encryption
        * @param kdf the key derivation function used for byte generation
        * @param mac the message authentication code generator for the message
        * @param cipher the cipher to used for encrypting the message
        */
        public IesEngine(IBasicAgreement agree, IDerivationFunction kdf, IMac mac, BufferedBlockCipher cipher)
        {
            _agree = agree;
            _kdf = kdf;
            _mac = mac;
            _macBuf = new byte[mac.GetMacSize()];
            _cipher = cipher;
        }

        public IBufferedCipher Cipher
        {
            get { return _cipher; }
        }

        public bool IsForEncryption { get; private set; }

        /**
        * Initialise the encryptor.
        *
        * @param forEncryption whether or not this is encryption/decryption.
        * @param privParam our private key parameters
        * @param pubParam the recipient's/sender's public key parameters
        * @param param encoding and derivation parameters.
        */
        public void Init(bool forEncryption, ICipherParameters privParameters, ICipherParameters pubParameters, ICipherParameters iesParameters)
        {
            this.IsForEncryption = forEncryption;
            _privParam = privParameters;
            _pubParam = pubParameters;
            _param = iesParameters as IesParameters;
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            var privParameters = forEncryption ? null : parameters;
            var pubParameters = forEncryption ? parameters : null;
            this.Init(forEncryption, privParameters, pubParameters, null);
        }

        private byte[] DecryptBlock(byte[] inEnc, int inOff, int inLen, byte[] z)
        {
            byte[] m;
            KeyParameter macKey;
            var kParam = new KdfParameters(z, _param.Derivation);
            var macKeySize = _param.MacKeySize;

            _kdf.Init(kParam);

            inLen -= _mac.GetMacSize();

            if (_cipher == null)     // stream mode
            {
                var buffer = GenerateKdfBytes(kParam, inLen + (macKeySize / 8));

                m = new byte[inLen];

                for (var i = 0; i != inLen; i++)
                {
                    m[i] = (byte)(inEnc[inOff + i] ^ buffer[i]);
                }

                macKey = new KeyParameter(buffer, inLen, (macKeySize / 8));
            }
            else
            {
                var cipherKeySize = ((IesWithCipherParameters)_param).CipherKeySize;
                var buffer = GenerateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

                _cipher.Init(false, new KeyParameter(buffer, 0, (cipherKeySize / 8)));

                m = _cipher.DoFinal(inEnc, inOff, inLen);

                macKey = new KeyParameter(buffer, (cipherKeySize / 8), (macKeySize / 8));
            }

            var macIV = _param.Encoding;

            _mac.Init(macKey);
            _mac.BlockUpdate(inEnc, inOff, inLen);
            _mac.BlockUpdate(macIV, 0, macIV.Length);
            _mac.DoFinal(_macBuf, 0);

            inOff += inLen;

            for (var t = 0; t < _macBuf.Length; t++)
            {
                if (_macBuf[t] != inEnc[inOff + t])
                {
                    throw (new InvalidCipherTextException("IMac codes failed to equal."));
                }
            }

            return m;
        }

        private byte[] EncryptBlock(byte[] input, int inOff, int inLen, byte[] z)
        {
            byte[] c;
            KeyParameter macKey;
            var kParam = new KdfParameters(z, _param.Derivation);
            int cTextLength;
            var macKeySize = _param.MacKeySize;

            if (_cipher == null)     // stream mode
            {
                var buffer = GenerateKdfBytes(kParam, inLen + (macKeySize / 8));

                c = new byte[inLen + _mac.GetMacSize()];
                cTextLength = inLen;

                for (var i = 0; i != inLen; i++)
                {
                    c[i] = (byte)(input[inOff + i] ^ buffer[i]);
                }

                macKey = new KeyParameter(buffer, inLen, (macKeySize / 8));
            }
            else
            {
                var cipherKeySize = ((IesWithCipherParameters)_param).CipherKeySize;
                var buffer = GenerateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

                _cipher.Init(true, new KeyParameter(buffer, 0, (cipherKeySize / 8)));

                cTextLength = _cipher.GetOutputSize(inLen);
                var tmp = new byte[cTextLength];

                var len = _cipher.ProcessBytes(input, inOff, inLen, tmp, 0);
                len += _cipher.DoFinal(tmp, len);

                c = new byte[len + _mac.GetMacSize()];
                cTextLength = len;

                Array.Copy(tmp, 0, c, 0, len);

                macKey = new KeyParameter(buffer, (cipherKeySize / 8), (macKeySize / 8));
            }

            var macIV = _param.Encoding;

            _mac.Init(macKey);
            _mac.BlockUpdate(c, 0, cTextLength);
            _mac.BlockUpdate(macIV, 0, macIV.Length);
            //
            // return the message and it's MAC
            //
            _mac.DoFinal(c, cTextLength);
            return c;
        }

        private byte[] GenerateKdfBytes(IDerivationParameters kParam, int length)
        {
            var buf = new byte[length];

            _kdf.Init(kParam);

            _kdf.GenerateBytes(buf, 0, buf.Length);

            return buf;
        }

        public byte[] ProcessBlock(byte[] input, int inOff, int inLen)
        {
            _agree.Init(_privParam);

            var z = _agree.CalculateAgreement(_pubParam);

            // TODO Check that this is right (...Unsigned? Check length?)
            var zBytes = z.ToByteArray();
            return this.IsForEncryption
                ? EncryptBlock(input, inOff, inLen, zBytes)
                : DecryptBlock(input, inOff, inLen, zBytes);
        }
    }

}

using System;

namespace Org.BouncyCastle.Crypto
{
    /**
    * a buffer wrapper for an asymmetric block cipher, allowing input
    * to be accumulated in a piecemeal fashion until final processing.
    */
    public class BufferedAsymmetricBlockCipher : BufferedCipherBase
    {
        private readonly IAsymmetricBlockCipher _cipher;

        private byte[] _buffer;
        private int _bufOff;

        /**
        * base constructor.
        *
        * @param cipher the cipher this buffering object wraps.
        */
        public BufferedAsymmetricBlockCipher(IAsymmetricBlockCipher cipher)
        {
            _cipher = cipher;
        }

        /**
        * return the amount of data sitting in the buffer.
        *
        * @return the amount of data sitting in the buffer.
        */
        internal int GetBufferPosition()
        {
            return _bufOff;
        }

        public override string AlgorithmName
        {
            get { return _cipher.AlgorithmName; }
        }

        public override int GetBlockSize()
        {
            return _cipher.GetInputBlockSize();
        }

        public override int GetOutputSize(int length)
        {
            return _cipher.GetOutputBlockSize();
        }

        public override int GetUpdateOutputSize(int length)
        {
            return 0;
        }

        /**
        * initialise the buffer and the underlying cipher.
        *
        * @param forEncryption if true the cipher is initialised for
        *  encryption, if false for decryption.
        * @param param the key and other data required by the cipher.
        */
        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.Reset();

            _cipher.Init(forEncryption, parameters);

            //
            // we allow for an extra byte where people are using their own padding
            // mechanisms on a raw cipher.
            //
            _buffer = new byte[_cipher.GetInputBlockSize() + (forEncryption ? 1 : 0)];
            _bufOff = 0;
        }

        public override byte[] ProcessByte(byte input)
        {
            if (_bufOff >= _buffer.Length)
                throw new DataLengthException("attempt to process message to long for cipher");

            _buffer[_bufOff++] = input;
            return null;
        }

        public override byte[] ProcessBytes(byte[] input, int inOff, int length)
        {
            if (length < 1)
                return null;

            if (input == null)
                throw new ArgumentNullException("input");
            if (_bufOff + length > _buffer.Length)
                throw new DataLengthException("attempt to process message to long for cipher");

            Array.Copy(input, inOff, _buffer, _bufOff, length);
            _bufOff += length;
            return null;
        }

        /**
        * process the contents of the buffer using the underlying
        * cipher.
        *
        * @return the result of the encryption/decryption process on the
        * buffer.
        * @exception InvalidCipherTextException if we are given a garbage block.
        */
        public override byte[] DoFinal()
        {
            var outBytes = _bufOff > 0
                ? _cipher.ProcessBlock(_buffer, 0, _bufOff)
                : EmptyBuffer;

            this.Reset();

            return outBytes;
        }

        public override byte[] DoFinal(byte[] input, int inOff, int length)
        {
            this.ProcessBytes(input, inOff, length);
            return DoFinal();
        }

        /// <summary>Reset the buffer</summary>
        public override void Reset()
        {
            if (_buffer == null) 
                return;

            Array.Clear(_buffer, 0, _buffer.Length);
            _bufOff = 0;
        }
    }
}

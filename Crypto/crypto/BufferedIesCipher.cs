using System;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;

namespace Org.BouncyCastle.Crypto
{
    public class BufferedIesCipher : BufferedCipherBase
    {
        private readonly IesEngine _engine;
        private readonly MemoryStream _buffer = new MemoryStream();

        public BufferedIesCipher(IesEngine engine)
        {
            if (engine == null)
                throw new ArgumentNullException("engine");

            _engine = engine;
        }

        public override string AlgorithmName
        {            
            get { return "IES+" + _engine.Cipher.AlgorithmName; }
        }        

        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            _engine.Init(forEncryption, parameters);
        }

        public override int GetBlockSize()
        {
            return _engine.Cipher.GetBlockSize();
        }

        public override int GetOutputSize(int inputLen)
        {
            if (_engine == null)
                throw new InvalidOperationException("cipher not initialised");

            var baseLen = inputLen + (int)_buffer.Length;
            return _engine.IsForEncryption
                ? baseLen + 20
                : baseLen - 20;
        }

        public override int GetUpdateOutputSize(int inputLen)
        {
            return _engine.Cipher.GetUpdateOutputSize(inputLen);
        }

        public override byte[] ProcessByte(byte input)
        {
            _buffer.WriteByte(input);
            return null;
        }

        public override byte[] ProcessBytes(byte[] input, int inOff, int length)
        {
            if (input == null)
                throw new ArgumentNullException("input");
            if (inOff < 0)
                throw new ArgumentException("inOff");
            if (length < 0)
                throw new ArgumentException("length");
            if (inOff + length > input.Length)
                throw new ArgumentException("invalid offset/length specified for input array");

            _buffer.Write(input, inOff, length);
            return null;
        }

        public override byte[] DoFinal()
        {
            var buf = _buffer.ToArray();
            this.Reset();
            return _engine.ProcessBlock(buf, 0, buf.Length);
        }

        public override byte[] DoFinal(byte[] input, int inOff, int length)
        {
            this.ProcessBytes(input, inOff, length);
            return this.DoFinal();
        }

        public override void Reset()
        {
            _buffer.SetLength(0);
        }
    }
}

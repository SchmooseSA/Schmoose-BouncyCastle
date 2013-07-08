using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithIV : ICipherParameters
    {
        private readonly ICipherParameters _parameters;
        private readonly byte[] _iv;

        public ParametersWithIV(ICipherParameters parameters, byte[] iv)
            : this(parameters, iv, 0, iv.Length)
        {
        }

        public ParametersWithIV(ICipherParameters parameters, byte[] iv, int ivOff, int ivLen)
        {
            if (parameters == null)
                throw new ArgumentNullException("parameters");
            if (iv == null)
                throw new ArgumentNullException("iv");

            _parameters = parameters;
            _iv = new byte[ivLen];
            Array.Copy(iv, ivOff, _iv, 0, ivLen);
        }

        public byte[] GetIV()
        {
            return (byte[])_iv.Clone();
        }

        public ICipherParameters Parameters
        {
            get { return _parameters; }
        }
    }
}

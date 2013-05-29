#if !NETCF_1_0

using System;
#if NETFX_CORE
using Windows.Security.Cryptography;
#else
using System.Security.Cryptography;
#endif

namespace Org.BouncyCastle.Crypto.Prng
{
	/// <summary>
	/// Uses Microsoft's RNGCryptoServiceProvider
	/// </summary>
	public class CryptoApiRandomGenerator : IRandomGenerator
	{
#if !NETFX_CORE
		private readonly RNGCryptoServiceProvider _rndProv;

		public CryptoApiRandomGenerator()
		{
			_rndProv = new RNGCryptoServiceProvider();
		}
#else



#endif

		#region IRandomGenerator Members

		public virtual void AddSeedMaterial(byte[] seed)
		{
			// We don't care about the seed
		}

		public virtual void AddSeedMaterial(long seed)
		{
			// We don't care about the seed
		}

		public virtual void NextBytes(byte[] bytes)
		{
            this.GetRandomBytes(bytes);
		}

		public virtual void NextBytes(byte[] bytes, int start, int len)
		{
			if (start < 0)
				throw new ArgumentException("Start offset cannot be negative", "start");
			if (bytes.Length < (start + len))
				throw new ArgumentException("Byte array too small for requested offset and length");

			if (bytes.Length == len && start == 0) 
			{
				NextBytes(bytes);
			}
			else 
			{
				var tmpBuf = new byte[len];
                this.GetRandomBytes(tmpBuf);
				Array.Copy(tmpBuf, 0, bytes, start, len);
			}
		}

        private void GetRandomBytes(byte[] bytes)
        {
#if NETFX_CORE
            var buffer = CryptographicBuffer.GenerateRandom(Convert.ToUInt32(bytes.Length));

            byte[] randomBytes;
            CryptographicBuffer.CopyToByteArray(buffer, out randomBytes);
            Buffer.BlockCopy(randomBytes, 0, bytes, 0, bytes.Length);
#else
            _rndProv.GetBytes(bytes);
#endif
        }

		#endregion
	}
}

#endif

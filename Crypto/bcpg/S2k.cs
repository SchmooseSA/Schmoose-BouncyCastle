using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>The string to key specifier class.</remarks>
    public class S2k : BcpgObject
    {
        private const int ExpBias = 6;

        public const int Simple = 0;
        public const int Salted = 1;
        public const int SaltedAndIterated = 3;
        public const int GnuDummyS2K = 101;

        private readonly int _type;
        private readonly HashAlgorithmTag _algorithm;
        private readonly byte[] _iv;
        private readonly int _itCount = -1;
        private readonly int _protectionMode = -1;

        /// <summary>
        /// Initializes a new instance of the <see cref="S2k"/> class.
        /// </summary>
        /// <param name="inStr">The in STR.</param>
        /// <exception cref="System.IO.EndOfStreamException"></exception>
        internal S2k(Stream inStr)
        {
			_type = inStr.ReadByte();
            _algorithm = (HashAlgorithmTag) inStr.ReadByte();

            //
            // if this happens we have a dummy-S2k packet.
            //
            if (_type != GnuDummyS2K)
            {
                if (_type != 0)
                {
					_iv = new byte[8];
					if (Streams.ReadFully(inStr, _iv, 0, _iv.Length) < _iv.Length)
						throw new EndOfStreamException();

					if (_type == 3)
					{
						_itCount = inStr.ReadByte();
					}
				}
            }
            else
            {
                inStr.ReadByte(); // G
                inStr.ReadByte(); // N
                inStr.ReadByte(); // U
                _protectionMode = inStr.ReadByte(); // protection mode
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="S2k"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public S2k(HashAlgorithmTag algorithm)
        {
            _type = 0;
            _algorithm = algorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="S2k"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="iv">The iv.</param>
        public S2k(HashAlgorithmTag algorithm, byte[] iv)
        {
            _type = 1;
            _algorithm = algorithm;
            _iv = iv;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="S2k"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="itCount">It count.</param>
        public S2k(HashAlgorithmTag algorithm, byte[] iv, int itCount)
        {
            _type = 3;
            _algorithm = algorithm;
            _iv = iv;
            _itCount = itCount;
        }

        public int Type
        {
			get { return _type; }
        }

		/// <summary>The hash algorithm.</summary>
        public HashAlgorithmTag HashAlgorithm
        {
			get { return _algorithm; }
		}

		/// <summary>The IV for the key generation algorithm.</summary>
        public byte[] GetIV()
        {
            return Arrays.Clone(_iv);
        }

		[Obsolete("Use 'IterationCount' property instead")]
        public long GetIterationCount()
        {
            return IterationCount;
        }

		/// <summary>The iteration count</summary>
		public long IterationCount
		{
			get { return (16 + (_itCount & 15)) << ((_itCount >> 4) + ExpBias); }
		}

		/// <summary>The protection mode - only if GnuDummyS2K</summary>
        public int ProtectionMode
        {
			get { return _protectionMode; }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteByte((byte) _type);
            bcpgOut.WriteByte((byte) _algorithm);

            if (_type != GnuDummyS2K)
            {
                if (_type != 0)
                {
                    bcpgOut.Write(_iv);
                }

                if (_type == 3)
                {
                    bcpgOut.WriteByte((byte) _itCount);
                }
            }
            else
            {
                bcpgOut.WriteByte((byte) 'G');
                bcpgOut.WriteByte((byte) 'N');
                bcpgOut.WriteByte((byte) 'U');
                bcpgOut.WriteByte((byte) _protectionMode);
            }
        }
    }
}

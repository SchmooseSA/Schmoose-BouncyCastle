using System;
using System.Diagnostics;
using System.IO;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpEncryptedData
    {
        protected class TruncatedStream : BaseInputStream
		{
			private const int LookAheadSize = 22;
			private const int LookAheadBufSize = 512;
			private const int LookAheadBufLimit = LookAheadBufSize - LookAheadSize;

			private readonly Stream _inStr;
			private readonly byte[] _lookAhead = new byte[LookAheadBufSize];
            private int _bufStart;
            private int _bufEnd;

			public TruncatedStream(Stream inStr)
			{
				var numRead = Streams.ReadFully(inStr, _lookAhead, 0, _lookAhead.Length);

				if (numRead < LookAheadSize)
					throw new EndOfStreamException();

				_inStr = inStr;
				_bufStart = 0;
				_bufEnd = numRead - LookAheadSize;
			}

			private int FillBuffer()
			{
				if (_bufEnd < LookAheadBufLimit)
					return 0;

				Debug.Assert(_bufStart == LookAheadBufLimit);
				Debug.Assert(_bufEnd == LookAheadBufLimit);

				Array.Copy(_lookAhead, LookAheadBufLimit, _lookAhead, 0, LookAheadSize);
				_bufEnd = Streams.ReadFully(_inStr, _lookAhead, LookAheadSize, LookAheadBufLimit);
				_bufStart = 0;
				return _bufEnd;
			}

			public override int ReadByte()
			{
				if (_bufStart < _bufEnd)
					return _lookAhead[_bufStart++];

				if (FillBuffer() < 1)
					return -1;

				return _lookAhead[_bufStart++];
			}

			public override int Read(byte[] buf, int off, int len)
			{
				var avail = _bufEnd - _bufStart;

				var pos = off;
				while (len > avail)
				{
					Array.Copy(_lookAhead, _bufStart, buf, pos, avail);

					_bufStart += avail;
					pos += avail;
					len -= avail;

					if ((avail = FillBuffer()) < 1)
						return pos - off;
				}

				Array.Copy(_lookAhead, _bufStart, buf, pos, len);
				_bufStart += len;

				return pos + len - off;
			}

			public byte[] GetLookAhead()
			{
			    var temp = new byte[LookAheadSize];
				Array.Copy(_lookAhead, _bufStart, temp, 0, LookAheadSize);
				return temp;
			}
		}

		protected InputStreamPacket	EncData;
        protected Stream EncStream;
        protected TruncatedStream TruncStream;

        protected PgpEncryptedData(InputStreamPacket encData)
        {
            this.EncData = encData;
        }

		/// <summary>Return the raw input stream for the data stream.</summary>
        public virtual Stream GetInputStream()
        {
            return EncData.GetInputStream();
        }

		/// <summary>Return true if the message is integrity protected.</summary>
		/// <returns>True, if there is a modification detection code namespace associated
		/// with this stream.</returns>
        public bool IsIntegrityProtected()
        {
			return EncData is SymmetricEncIntegrityPacket;
        }

		/// <summary>Note: This can only be called after the message has been read.</summary>
		/// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!IsIntegrityProtected())
                throw new PgpException("data not integrity protected.");

			var dIn = (DigestStream) EncStream;

			//
            // make sure we are at the end.
            //
            while (EncStream.ReadByte() >= 0)
            {
				// do nothing
            }

			//
            // process the MDC packet
            //
			var lookAhead = TruncStream.GetLookAhead();

			var hash = dIn.ReadDigest();
			hash.BlockUpdate(lookAhead, 0, 2);

			var digest = DigestUtilities.DoFinal(hash);
			var streamDigest = new byte[digest.Length];
			Array.Copy(lookAhead, 2, streamDigest, 0, streamDigest.Length);

			return Arrays.ConstantTimeAreEqual(digest, streamDigest);
        }
    }
}

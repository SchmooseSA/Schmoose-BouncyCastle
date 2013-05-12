using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
    /**
    * A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
    * be used to produce cipher text which is the same outLength as the plain text.
    */
    public class CtsBlockCipher
		: BufferedBlockCipher
    {
        private readonly int blockSize;

        /**
        * Create a buffered block cipher that uses Cipher Text Stealing
        *
        * @param cipher the underlying block cipher this buffering object wraps.
        */
        public CtsBlockCipher(
            IBlockCipher cipher)
        {
			// TODO Should this test for acceptable ones instead?
			if (cipher is OfbBlockCipher || cipher is CfbBlockCipher)
                throw new ArgumentException("CtsBlockCipher can only accept ECB, or CBC ciphers");

			this.Cipher = cipher;

            blockSize = cipher.GetBlockSize();

            Buffer = new byte[blockSize * 2];
            BufferOffset = 0;
        }

        /**
        * return the size of the output buffer required for an update of 'length' bytes.
        *
        * @param length the outLength of the input.
        * @return the space required to accommodate a call to update
        * with length bytes of input.
        */
        public override int GetUpdateOutputSize(
            int length)
        {
            int total = length + BufferOffset;
            int leftOver = total % Buffer.Length;

			if (leftOver == 0)
            {
                return total - Buffer.Length;
            }

			return total - leftOver;
        }

        /**
        * return the size of the output buffer required for an update plus a
        * doFinal with an input of length bytes.
        *
        * @param length the outLength of the input.
        * @return the space required to accommodate a call to update and doFinal
        * with length bytes of input.
        */
        public override int GetOutputSize(
            int length)
        {
            return length + BufferOffset;
        }

        /**
        * process a single byte, producing an output block if neccessary.
        *
        * @param in the input byte.
        * @param out the space for any output that might be produced.
        * @param outOff the offset from which the output will be copied.
        * @return the number of output bytes copied to out.
        * @exception DataLengthException if there isn't enough space in out.
        * @exception InvalidOperationException if the cipher isn't initialised.
        */
        public override int ProcessByte(
            byte	input,
            byte[]	output,
            int		outOff)
        {
            int resultLen = 0;

            if (BufferOffset == Buffer.Length)
            {
                resultLen = Cipher.ProcessBlock(Buffer, 0, output, outOff);
				Debug.Assert(resultLen == blockSize);

				Array.Copy(Buffer, blockSize, Buffer, 0, blockSize);
                BufferOffset = blockSize;
            }

            Buffer[BufferOffset++] = input;

            return resultLen;
        }

		/**
        * process an array of bytes, producing output if necessary.
        *
        * @param in the input byte array.
        * @param inOff the offset at which the input data starts.
        * @param length the number of bytes to be copied out of the input array.
        * @param out the space for any output that might be produced.
        * @param outOff the offset from which the output will be copied.
        * @return the number of output bytes copied to out.
        * @exception DataLengthException if there isn't enough space in out.
        * @exception InvalidOperationException if the cipher isn't initialised.
        */
        public override int ProcessBytes(
            byte[]	input,
            int		inOff,
            int		length,
            byte[]	output,
            int		outOff)
        {
            if (length < 0)
            {
                throw new ArgumentException("Can't have a negative input outLength!");
            }

            int blockSize = GetBlockSize();
            int outLength = GetUpdateOutputSize(length);

            if (outLength > 0)
            {
                if ((outOff + outLength) > output.Length)
                {
                    throw new DataLengthException("output buffer too short");
                }
            }

            int resultLen = 0;
            int gapLen = Buffer.Length - BufferOffset;

            if (length > gapLen)
            {
                Array.Copy(input, inOff, Buffer, BufferOffset, gapLen);

                resultLen += Cipher.ProcessBlock(Buffer, 0, output, outOff);
                Array.Copy(Buffer, blockSize, Buffer, 0, blockSize);

                BufferOffset = blockSize;

                length -= gapLen;
                inOff += gapLen;

                while (length > blockSize)
                {
                    Array.Copy(input, inOff, Buffer, BufferOffset, blockSize);
                    resultLen += Cipher.ProcessBlock(Buffer, 0, output, outOff + resultLen);
                    Array.Copy(Buffer, blockSize, Buffer, 0, blockSize);

                    length -= blockSize;
                    inOff += blockSize;
                }
            }

            Array.Copy(input, inOff, Buffer, BufferOffset, length);

            BufferOffset += length;

            return resultLen;
        }

        /**
        * Process the last block in the buffer.
        *
        * @param out the array the block currently being held is copied into.
        * @param outOff the offset at which the copying starts.
        * @return the number of output bytes copied to out.
        * @exception DataLengthException if there is insufficient space in out for
        * the output.
        * @exception InvalidOperationException if the underlying cipher is not
        * initialised.
        * @exception InvalidCipherTextException if cipher text decrypts wrongly (in
        * case the exception will never Get thrown).
        */
        public override int DoFinal(
            byte[]  output,
            int     outOff)
        {
            if (BufferOffset + outOff > output.Length)
            {
                throw new DataLengthException("output buffer too small in doFinal");
            }

            int blockSize = Cipher.GetBlockSize();
            int length = BufferOffset - blockSize;
            byte[] block = new byte[blockSize];

            if (ForEncryption)
            {
                Cipher.ProcessBlock(Buffer, 0, block, 0);

				if (BufferOffset < blockSize)
				{
					throw new DataLengthException("need at least one block of input for CTS");
				}

                for (int i = BufferOffset; i != Buffer.Length; i++)
                {
                    Buffer[i] = block[i - blockSize];
                }

                for (int i = blockSize; i != BufferOffset; i++)
                {
                    Buffer[i] ^= block[i - blockSize];
                }

				IBlockCipher c = (Cipher is CbcBlockCipher)
					?	((CbcBlockCipher)Cipher).GetUnderlyingCipher()
					:	Cipher;

				c.ProcessBlock(Buffer, blockSize, output, outOff);

				Array.Copy(block, 0, output, outOff + blockSize, length);
            }
            else
            {
                byte[] lastBlock = new byte[blockSize];

				IBlockCipher c = (Cipher is CbcBlockCipher)
					?	((CbcBlockCipher)Cipher).GetUnderlyingCipher()
					:	Cipher;

				c.ProcessBlock(Buffer, 0, block, 0);

				for (int i = blockSize; i != BufferOffset; i++)
                {
                    lastBlock[i - blockSize] = (byte)(block[i - blockSize] ^ Buffer[i]);
                }

                Array.Copy(Buffer, blockSize, block, 0, length);

                Cipher.ProcessBlock(block, 0, output, outOff);
                Array.Copy(lastBlock, 0, output, outOff + blockSize, length);
            }

            int offset = BufferOffset;

            Reset();

            return offset;
        }
    }
}

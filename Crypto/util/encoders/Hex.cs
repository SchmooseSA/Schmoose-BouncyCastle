using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Utilities.Encoders
{
    /// <summary>
    /// Class to decode and encode Hex.
    /// </summary>
    public static class Hex
    {
        private static readonly IEncoder _encoder = new HexEncoder();

        public static string ToHexString(byte[] data)
        {
            var hex = Encode(data, 0, data.Length);
            return Strings.FromAsciiByteArray(hex);
        }

        public static string ToHexString(byte[] data, int off, int length)
        {
            var hex = Encode(data, off, length);
            return Strings.FromAsciiByteArray(hex);
        }

        /**
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
        public static byte[] Encode(byte[] data)
        {
            return Encode(data, 0, data.Length);
        }

        /**
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
        public static byte[] Encode(byte[] data, int off, int length)
        {
            using (var bOut = new MemoryStream(length*2))
            {
                _encoder.Encode(data, off, length, bOut);
                return bOut.ToArray();
            }
        }

        /**
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int Encode( byte[] data, Stream outStream)
        {
            return _encoder.Encode(data, 0, data.Length, outStream);
        }

        /**
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int Encode(byte[] data, int off, int length, Stream outStream)
        {
            return _encoder.Encode(data, off, length, outStream);
        }

        /**
         * decode the Hex encoded input data. It is assumed the input data is valid.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] Decode(byte[] data)
        {
            using (var bOut = new MemoryStream((data.Length + 1)/2))
            {
                _encoder.Decode(data, 0, data.Length, bOut);
                return bOut.ToArray();
            }
        }

        /**
         * decode the Hex encoded string data - whitespace will be ignored.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] Decode(string data)
        {
            using (var bOut = new MemoryStream((data.Length + 1) / 2))
            {
                _encoder.DecodeString(data, bOut);
                return bOut.ToArray();
            }
        }

        /**
         * decode the Hex encoded string data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
        public static int Decode(string data, Stream outStream)
        {
            return _encoder.DecodeString(data, outStream);
        }

        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) 
                return "<null>";

            var bytesLength = bytes.Length;

            const int firstHexColumn = 11;
            var firstCharColumn = firstHexColumn
                + bytesPerLine * 3
                + (bytesPerLine - 1) / 8
                + 2;                  

            var lineLength = firstCharColumn
                + bytesPerLine
                + Environment.NewLine.Length;

            var line = (new String(' ', lineLength - 2) + Environment.NewLine).ToCharArray();
            var expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            var result = new StringBuilder(expectedLines * lineLength);

            for (var i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = (char)HexEncoder.EncodingTable[(i >> 28) & 0xF];
                line[1] = (char)HexEncoder.EncodingTable[(i >> 24) & 0xF];
                line[2] = (char)HexEncoder.EncodingTable[(i >> 20) & 0xF];
                line[3] = (char)HexEncoder.EncodingTable[(i >> 16) & 0xF];
                line[4] = (char)HexEncoder.EncodingTable[(i >> 12) & 0xF];
                line[5] = (char)HexEncoder.EncodingTable[(i >> 8) & 0xF];
                line[6] = (char)HexEncoder.EncodingTable[(i >> 4) & 0xF];
                line[7] = (char)HexEncoder.EncodingTable[(i >> 0) & 0xF];

                var hexColumn = firstHexColumn;
                var charColumn = firstCharColumn;

                for (var j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        var b = bytes[i + j];
                        line[hexColumn] = (char)HexEncoder.EncodingTable[(b >> 4) & 0xF];
                        line[hexColumn + 1] = (char)HexEncoder.EncodingTable[b & 0xF];
                        line[charColumn] = (b < 32 ? '.' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }
    }
}

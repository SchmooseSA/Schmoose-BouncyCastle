using System.IO;

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
    }
}

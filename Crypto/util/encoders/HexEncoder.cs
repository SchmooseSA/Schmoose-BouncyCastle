using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
    public class HexEncoder : IEncoder
    {
        public static readonly byte[] EncodingTable =
		{
			(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
			(byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
		};

        /*
        * set up the decoding table.
        */
        internal static readonly byte[] DecodingTable = new byte[128];

        static HexEncoder()
        {
            for (var i = 0; i < EncodingTable.Length; i++)
            {
                DecodingTable[EncodingTable[i]] = (byte)i;
            }

            DecodingTable['A'] = DecodingTable['a'];
            DecodingTable['B'] = DecodingTable['b'];
            DecodingTable['C'] = DecodingTable['c'];
            DecodingTable['D'] = DecodingTable['d'];
            DecodingTable['E'] = DecodingTable['e'];
            DecodingTable['F'] = DecodingTable['f'];
        }

        /**
        * encode the input data producing a Hex output stream.
        *
        * @return the number of bytes produced.
        */
        public int Encode(byte[] data, int off, int length, Stream outStream)
        {
            for (var i = off; i < (off + length); i++)
            {
                int v = data[i];

                outStream.WriteByte(EncodingTable[v >> 4]);
                outStream.WriteByte(EncodingTable[v & 0xf]);
            }

            return length * 2;
        }

        private static bool Ignore(char c)
        {
            return (c == '\n' || c == '\r' || c == '\t' || c == ' ');
        }

        /**
        * decode the Hex encoded byte data writing it to the given output stream,
        * whitespace characters will be ignored.
        *
        * @return the number of bytes produced.
        */
        public int Decode(byte[] data, int off, int length, Stream outStream)
        {
            var outLen = 0;
            var end = off + length;

            while (end > off)
            {
                if (!Ignore((char)data[end - 1]))
                {
                    break;
                }

                end--;
            }

            var i = off;
            while (i < end)
            {
                while (i < end && Ignore((char)data[i]))
                {
                    i++;
                }

                var b1 = DecodingTable[data[i++]];

                while (i < end && Ignore((char)data[i]))
                {
                    i++;
                }

                byte b2 = DecodingTable[data[i++]];

                outStream.WriteByte((byte)((b1 << 4) | b2));

                outLen++;
            }

            return outLen;
        }

        /**
        * decode the Hex encoded string data writing it to the given output stream,
        * whitespace characters will be ignored.
        *
        * @return the number of bytes produced.
        */
        public int DecodeString(string data, Stream outStream)
        {
            var length = 0;
            var end = data.Length;
            while (end > 0)
            {
                if (!Ignore(data[end - 1]))
                {
                    break;
                }

                end--;
            }

            var i = 0;
            while (i < end)
            {
                while (i < end && Ignore(data[i]))
                {
                    i++;
                }

                var b1 = DecodingTable[data[i++]];

                while (i < end && Ignore(data[i]))
                {
                    i++;
                }

                var b2 = DecodingTable[data[i++]];

                outStream.WriteByte((byte)((b1 << 4) | b2));

                length++;
            }

            return length;
        }
    }
}

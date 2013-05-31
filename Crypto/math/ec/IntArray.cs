using System;
using System.Text;

namespace Org.BouncyCastle.Math.EC
{
	internal class IntArray
    {
        // TODO make m fixed for the IntArray, and hence compute T once and for all

		// TODO Use uint's internally?
		private int[] _ints;

		public IntArray(int intLen)
		{
			_ints = new int[intLen];
		}

		private IntArray(int[] ints)
		{
			_ints = ints;
		}

        public IntArray(IBigInteger bigInt)
			: this(bigInt, 0)
		{
		}

        public IntArray(IBigInteger bigInt, int minIntLen)
		{
			if (bigInt.SignValue == -1)
                throw new ArgumentException(@"Only positive Integers allowed", "bigInt");

			if (bigInt.SignValue == 0)
			{
				_ints = new int[] { 0 };
				return;
			}

			var barr = bigInt.ToByteArrayUnsigned();
			var barrLen = barr.Length;

			var intLen = (barrLen + 3) / 4;
			_ints = new int[System.Math.Max(intLen, minIntLen)];

			var rem = barrLen % 4;
			var barrI = 0;

			if (0 < rem)
			{
				var temp = (int) barr[barrI++];
				while (barrI < rem)
				{
					temp = temp << 8 | (int) barr[barrI++];
				}
				_ints[--intLen] = temp;
			}

			while (intLen > 0)
			{
				var temp = (int) barr[barrI++];
				for (var i = 1; i < 4; i++)
				{
					temp = temp << 8 | (int) barr[barrI++];
				}
				_ints[--intLen] = temp;
			}
		}

		public int GetUsedLength()
		{
			int highestIntPos = _ints.Length;

			if (highestIntPos < 1)
				return 0;

			// Check if first element will act as sentinel
			if (_ints[0] != 0)
			{
				while (_ints[--highestIntPos] == 0)
				{
				}
				return highestIntPos + 1;
			}

			do
			{
				if (_ints[--highestIntPos] != 0)
				{
					return highestIntPos + 1;
				}
			}
			while (highestIntPos > 0);

			return 0;
		}

		public int BitLength
		{
			get
			{
				// JDK 1.5: see Integer.numberOfLeadingZeros()
				int intLen = GetUsedLength();
				if (intLen == 0)
					return 0;

				var last = intLen - 1;
				var highest = (uint) _ints[last];
				var bits = (last << 5) + 1;

				// A couple of binary search steps
				if (highest > 0x0000ffff)
				{
					if (highest > 0x00ffffff)
					{
						bits += 24;
						highest >>= 24;
					}
					else
					{
						bits += 16;
						highest >>= 16;
					}
				}
				else if (highest > 0x000000ff)
				{
					bits += 8;
					highest >>= 8;
				}

				while (highest > 1)
				{
					++bits;
					highest >>= 1;
				}

				return bits;
			}
		}

		private int[] ResizedInts(int newLen)
		{
			var newInts = new int[newLen];
			var oldLen = _ints.Length;
			var copyLen = oldLen < newLen ? oldLen : newLen;
			Array.Copy(_ints, 0, newInts, 0, copyLen);
			return newInts;
		}

        public IBigInteger ToBigInteger()
		{
			var usedLen = GetUsedLength();
			if (usedLen == 0)
			{
				return BigInteger.Zero;
			}

			var highestInt = _ints[usedLen - 1];
			var temp = new byte[4];
			var barrI = 0;
			var trailingZeroBytesDone = false;
			for (var j = 3; j >= 0; j--)
			{
				var thisByte = (byte)((int)((uint) highestInt >> (8 * j)));
			    if (!trailingZeroBytesDone && (thisByte == 0)) 
                    continue;

			    trailingZeroBytesDone = true;
			    temp[barrI++] = thisByte;
			}

			var barrLen = 4 * (usedLen - 1) + barrI;
			var barr = new byte[barrLen];
			for (var j = 0; j < barrI; j++)
			{
				barr[j] = temp[j];
			}
			// Highest value int is done now

			for (var iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--)
			{
				for (var j = 3; j >= 0; j--)
				{
					barr[barrI++] = (byte)((int)((uint)_ints[iarrJ] >> (8 * j)));
				}
			}
			return new BigInteger(1, barr);
		}

		public void ShiftLeft()
		{
			int usedLen = GetUsedLength();
			if (usedLen == 0)
			{
				return;
			}
			if (_ints[usedLen - 1] < 0)
			{
				// highest bit of highest used byte is set, so shifting left will
				// make the IntArray one byte longer
				usedLen++;
				if (usedLen > _ints.Length)
				{
					// make the m_ints one byte longer, because we need one more
					// byte which is not available in m_ints
					_ints = ResizedInts(_ints.Length + 1);
				}
			}

			bool carry = false;
			for (int i = 0; i < usedLen; i++)
			{
				// nextCarry is true if highest bit is set
				bool nextCarry = _ints[i] < 0;
				_ints[i] <<= 1;
				if (carry)
				{
					// set lowest bit
					_ints[i] |= 1;
				}
				carry = nextCarry;
			}
		}

		public IntArray ShiftLeft(int n)
		{
			var usedLen = GetUsedLength();
			if (usedLen == 0)
			{
				return this;
			}

			if (n == 0)
			{
				return this;
			}

			if (n > 31)
			{
				throw new ArgumentException("shiftLeft() for max 31 bits "
					+ ", " + n + "bit shift is not possible", "n");
			}

			var newInts = new int[usedLen + 1];

			var nm32 = 32 - n;
			newInts[0] = _ints[0] << n;
			for (var i = 1; i < usedLen; i++)
			{
				newInts[i] = (_ints[i] << n) | (int)((uint)_ints[i - 1] >> nm32);
			}
			newInts[usedLen] = (int)((uint)_ints[usedLen - 1] >> nm32);

			return new IntArray(newInts);
		}

		public void AddShifted(IntArray other, int shift)
		{
			var usedLenOther = other.GetUsedLength();
			var newMinUsedLen = usedLenOther + shift;
			if (newMinUsedLen > _ints.Length)
			{
				_ints = ResizedInts(newMinUsedLen);
				//Console.WriteLine("Resize required");
			}

			for (var i = 0; i < usedLenOther; i++)
			{
				_ints[i + shift] ^= other._ints[i];
			}
		}

		public int Length
		{
			get { return _ints.Length; }
		}

		public bool TestBit(int n)
		{
			// theInt = n / 32
			var theInt = n >> 5;
			// theBit = n % 32
			var theBit = n & 0x1F;
			var tester = 1 << theBit;
			return ((_ints[theInt] & tester) != 0);
		}

		public void FlipBit(int n)
		{
			// theInt = n / 32
			var theInt = n >> 5;
			// theBit = n % 32
			var theBit = n & 0x1F;
			var flipper = 1 << theBit;
			_ints[theInt] ^= flipper;
		}

		public void SetBit(int n)
		{
			// theInt = n / 32
			var theInt = n >> 5;
			// theBit = n % 32
			var theBit = n & 0x1F;
			var setter = 1 << theBit;
			_ints[theInt] |= setter;
		}

		public IntArray Multiply(IntArray other, int m)
		{
			// Lenght of c is 2m bits rounded up to the next int (32 bit)
			var t = (m + 31) >> 5;
			if (_ints.Length < t)
			{
				_ints = ResizedInts(t);
			}

			var b = new IntArray(other.ResizedInts(other.Length + 1));
			var c = new IntArray((m + m + 31) >> 5);
			// IntArray c = new IntArray(t + t);
			int testBit = 1;
			for (int k = 0; k < 32; k++)
			{
				for (int j = 0; j < t; j++)
				{
					if ((_ints[j] & testBit) != 0)
					{
						// The kth bit of m_ints[j] is set
						c.AddShifted(b, j);
					}
				}
				testBit <<= 1;
				b.ShiftLeft();
			}
			return c;
		}

		// public IntArray multiplyLeftToRight(IntArray other, int m) {
		// // Lenght of c is 2m bits rounded up to the next int (32 bit)
		// int t = (m + 31) / 32;
		// if (m_ints.Length < t) {
		// m_ints = resizedInts(t);
		// }
		//
		// IntArray b = new IntArray(other.resizedInts(other.getLength() + 1));
		// IntArray c = new IntArray((m + m + 31) / 32);
		// // IntArray c = new IntArray(t + t);
		// int testBit = 1 << 31;
		// for (int k = 31; k >= 0; k--) {
		// for (int j = 0; j < t; j++) {
		// if ((m_ints[j] & testBit) != 0) {
		// // The kth bit of m_ints[j] is set
		// c.addShifted(b, j);
		// }
		// }
		// testBit >>>= 1;
		// if (k > 0) {
		// c.shiftLeft();
		// }
		// }
		// return c;
		// }

		// TODO note, redPol.Length must be 3 for TPB and 5 for PPB
		public void Reduce(int m, int[] redPol)
		{
			for (var i = m + m - 2; i >= m; i--)
			{
			    if (!TestBit(i)) 
                    continue;

			    var bit = i - m;
			    FlipBit(bit);
			    FlipBit(i);
			    var l = redPol.Length;
			    while (--l >= 0)
			    {
			        FlipBit(redPol[l] + bit);
			    }
			}
			_ints = ResizedInts((m + 31) >> 5);
		}

		public IntArray Square(int m)
		{
			// TODO make the table static readonly
			int[] table = { 0x0, 0x1, 0x4, 0x5, 0x10, 0x11, 0x14, 0x15, 0x40,
									0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 };

			var t = (m + 31) >> 5;
			if (_ints.Length < t)
			{
				_ints = ResizedInts(t);
			}

			var c = new IntArray(t + t);

			// TODO twice the same code, put in separate private method
			for (var i = 0; i < t; i++)
			{
				var v0 = 0;
				for (var j = 0; j < 4; j++)
				{
					v0 = (int)((uint) v0 >> 8);
					var u = (int)((uint)_ints[i] >> (j * 4)) & 0xF;
					var w = table[u] << 24;
					v0 |= w;
				}
				c._ints[i + i] = v0;

				v0 = 0;
				var upper = (int)((uint) _ints[i] >> 16);
				for (var j = 0; j < 4; j++)
				{
					v0 = (int)((uint) v0 >> 8);
					var u = (int)((uint)upper >> (j * 4)) & 0xF;
					var w = table[u] << 24;
					v0 |= w;
				}
				c._ints[i + i + 1] = v0;
			}
			return c;
		}

		public override bool Equals(object o)
		{
			if (!(o is IntArray))
			{
				return false;
			}
			var other = (IntArray) o;
			var usedLen = GetUsedLength();
			if (other.GetUsedLength() != usedLen)
			{
				return false;
			}
			for (var i = 0; i < usedLen; i++)
			{
				if (_ints[i] != other._ints[i])
				{
					return false;
				}
			}
			return true;
		}

		public override int GetHashCode()
		{
			var i = GetUsedLength();
			var hc = i;
			while (--i >= 0)
			{
				hc *= 17;
				hc ^= _ints[i];
			}
			return hc;
		}

		internal IntArray Copy()
		{
			return new IntArray((int[]) _ints.Clone());
		}

		public override string ToString()
		{
			var usedLen = GetUsedLength();
			if (usedLen == 0)
			{
				return "0";
			}

			var sb = new StringBuilder(Convert.ToString(_ints[usedLen - 1], 2));
			for (var iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--)
			{
				var hexString = Convert.ToString(_ints[iarrJ], 2);

				// Add leading zeroes, except for highest significant int
				for (var i = hexString.Length; i < 8; i++)
				{
					hexString = "0" + hexString;
				}
				sb.Append(hexString);
			}
			return sb.ToString();
		}
	}
}

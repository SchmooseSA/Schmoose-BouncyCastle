using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
	public class Srp6Utilities
	{
		public static IBigInteger CalculateK(IDigest digest, IBigInteger N, IBigInteger g)
		{
			return HashPaddedPair(digest, N, N, g);
		}

	    public static IBigInteger CalculateU(IDigest digest, IBigInteger N, IBigInteger A, IBigInteger B)
	    {
	    	return HashPaddedPair(digest, N, A, B);
	    }

		public static IBigInteger CalculateX(IDigest digest, IBigInteger N, byte[] salt, byte[] identity, byte[] password)
	    {
	        byte[] output = new byte[digest.GetDigestSize()];

	        digest.BlockUpdate(identity, 0, identity.Length);
	        digest.Update((byte)':');
	        digest.BlockUpdate(password, 0, password.Length);
	        digest.DoFinal(output, 0);

	        digest.BlockUpdate(salt, 0, salt.Length);
	        digest.BlockUpdate(output, 0, output.Length);
	        digest.DoFinal(output, 0);

	        return new BigInteger(1, output).Mod(N);
	    }

		public static IBigInteger GeneratePrivateValue(IDigest digest, IBigInteger N, IBigInteger g, SecureRandom random)
	    {
			int minBits = System.Math.Min(256, N.BitLength / 2);
	        IBigInteger min = BigInteger.One.ShiftLeft(minBits - 1);
	        IBigInteger max = N.Subtract(BigInteger.One);

	        return BigIntegers.CreateRandomInRange(min, max, random);
	    }

		public static IBigInteger ValidatePublicValue(IBigInteger N, IBigInteger val)
		{
		    val = val.Mod(N);

	        // Check that val % N != 0
	        if (val.Equals(BigInteger.Zero))
	            throw new CryptoException("Invalid public value: 0");

		    return val;
		}

		private static IBigInteger HashPaddedPair(IDigest digest, IBigInteger N, IBigInteger n1, IBigInteger n2)
		{
	    	int padLength = (N.BitLength + 7) / 8;

	    	byte[] n1_bytes = GetPadded(n1, padLength);
	    	byte[] n2_bytes = GetPadded(n2, padLength);

	        digest.BlockUpdate(n1_bytes, 0, n1_bytes.Length);
	        digest.BlockUpdate(n2_bytes, 0, n2_bytes.Length);

	        byte[] output = new byte[digest.GetDigestSize()];
	        digest.DoFinal(output, 0);

	        return new BigInteger(1, output).Mod(N);
		}

		private static byte[] GetPadded(IBigInteger n, int length)
		{
			byte[] bs = BigIntegers.AsUnsignedByteArray(n);
			if (bs.Length < length)
			{
				byte[] tmp = new byte[length];
				Array.Copy(bs, 0, tmp, length - bs.Length, bs.Length);
				bs = tmp;
			}
			return bs;
		}
	}
}

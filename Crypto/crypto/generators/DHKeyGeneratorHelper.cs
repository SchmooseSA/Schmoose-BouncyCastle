using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
	class DHKeyGeneratorHelper
	{
		internal static readonly DHKeyGeneratorHelper Instance = new DHKeyGeneratorHelper();

		private DHKeyGeneratorHelper()
		{
		}

		internal IBigInteger CalculatePrivate(
			DHParameters	dhParams,
			ISecureRandom	random)
		{
			int limit = dhParams.L;

			if (limit != 0)
			{
				return new BigInteger(limit, random).SetBit(limit - 1);
			}

			IBigInteger min = BigInteger.Two;
			int m = dhParams.M;
			if (m != 0)
			{
				min = BigInteger.One.ShiftLeft(m - 1);
			}

			IBigInteger max = dhParams.P.Subtract(BigInteger.Two);
			IBigInteger q = dhParams.Q;
			if (q != null)
			{
				max = q.Subtract(BigInteger.Two);
			}

			return BigIntegers.CreateRandomInRange(min, max, random);
		}

		internal IBigInteger CalculatePublic(
			DHParameters	dhParams,
			IBigInteger		x)
		{
			return dhParams.G.ModPow(x, dhParams.P);
		}
	}
}

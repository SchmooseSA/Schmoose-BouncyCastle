using System;
using System.Collections;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Generators
{
	/**
	 * Key generation parameters for NaccacheStern cipher. For details on this cipher, please see
	 *
	 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	 */
	public class NaccacheSternKeyPairGenerator
		: IAsymmetricCipherKeyPairGenerator
	{
		private static readonly int[] smallPrimes =
		{
			3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
			71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
			151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
			239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
			337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
			433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
			541, 547, 557
		};

		private NaccacheSternKeyGenerationParameters param;

		/*
		 * (non-Javadoc)
		 *
		 * @see org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator#init(org.bouncycastle.crypto.KeyGenerationParameters)
		 */
		public void Init(IKeyGenerationParameters parameters)
		{
			this.param = (NaccacheSternKeyGenerationParameters)parameters;
		}

		/*
		 * (non-Javadoc)
		 *
		 * @see org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator#generateKeyPair()
		 */
		public IAsymmetricCipherKeyPair GenerateKeyPair()
		{
			int strength = param.Strength;
			ISecureRandom rand = param.Random;
			int certainty = param.Certainty;
			bool debug = param.IsDebug;

			if (debug)
			{
				Console.WriteLine("Fetching first " + param.CountSmallPrimes + " primes.");
			}

			IList smallPrimes = findFirstPrimes(param.CountSmallPrimes);

			smallPrimes = PermuteList(smallPrimes, rand);

            IBigInteger u = BigInteger.One;
            IBigInteger v = BigInteger.One;

			for (int i = 0; i < smallPrimes.Count / 2; i++)
			{
				u = u.Multiply((BigInteger)smallPrimes[i]);
			}
			for (int i = smallPrimes.Count / 2; i < smallPrimes.Count; i++)
			{
				v = v.Multiply((BigInteger)smallPrimes[i]);
			}

			IBigInteger sigma = u.Multiply(v);

			// n = (2 a u _p + 1 ) ( 2 b v _q + 1)
			// -> |n| = strength
			// |2| = 1 in bits
			// -> |a| * |b| = |n| - |u| - |v| - |_p| - |_q| - |2| -|2|
			// remainingStrength = strength - sigma.bitLength() - _p.bitLength() -
			// _q.bitLength() - 1 -1
			int remainingStrength = strength - sigma.BitLength - 48;
            IBigInteger a = GeneratePrime(remainingStrength / 2 + 1, certainty, rand);
            IBigInteger b = GeneratePrime(remainingStrength / 2 + 1, certainty, rand);

            IBigInteger _p;
            IBigInteger _q;
            IBigInteger p;
            IBigInteger q;

			long tries = 0;
			if (debug)
			{
				Console.WriteLine("generating p and q");
			}

            IBigInteger _2au = a.Multiply(u).ShiftLeft(1);
            IBigInteger _2bv = b.Multiply(v).ShiftLeft(1);

			for (;;)
			{
				tries++;

				_p = GeneratePrime(24, certainty, rand);

				p = _p.Multiply(_2au).Add(BigInteger.One);

				if (!p.IsProbablePrime(certainty))
					continue;

				for (;;)
				{
					_q = GeneratePrime(24, certainty, rand);

					if (_p.Equals(_q))
						continue;

					q = _q.Multiply(_2bv).Add(BigInteger.One);

					if (q.IsProbablePrime(certainty))
						break;
				}

				if (!sigma.Gcd(_p.Multiply(_q)).Equals(BigInteger.One))
				{
					Console.WriteLine("sigma.gcd(_p.mult(_q)) != 1!\n _p: " + _p +"\n _q: "+ _q );
					continue;
				}

				if (p.Multiply(q).BitLength < strength)
				{
					if (debug)
					{
						Console.WriteLine("key size too small. Should be " + strength + " but is actually "
							+ p.Multiply(q).BitLength);
					}
					continue;
				}
				break;
			}

			if (debug)
			{
				Console.WriteLine("needed " + tries + " tries to generate p and q.");
			}

			IBigInteger n = p.Multiply(q);
			IBigInteger phi_n = p.Subtract(BigInteger.One).Multiply(q.Subtract(BigInteger.One));
			IBigInteger g;
			tries = 0;
			if (debug)
			{
				Console.WriteLine("generating g");
			}
			for (;;)
			{
				// TODO After the first loop, just regenerate one randomly-selected gPart each time?
				IList gParts = Platform.CreateArrayList();
				for (int ind = 0; ind != smallPrimes.Count; ind++)
				{
					IBigInteger i = (BigInteger)smallPrimes[ind];
					IBigInteger e = phi_n.Divide(i);

					for (;;)
					{
						tries++;

						g = GeneratePrime(strength, certainty, rand);

						if (!g.ModPow(e, n).Equals(BigInteger.One))
						{
							gParts.Add(g);
							break;
						}
					}
				}
				g = BigInteger.One;
				for (int i = 0; i < smallPrimes.Count; i++)
				{
					IBigInteger gPart = (BigInteger) gParts[i];
					IBigInteger smallPrime = (BigInteger) smallPrimes[i];
					g = g.Multiply(gPart.ModPow(sigma.Divide(smallPrime), n)).Mod(n);
				}

				// make sure that g is not divisible by p_i or q_i
				bool divisible = false;
				for (int i = 0; i < smallPrimes.Count; i++)
				{
					if (g.ModPow(phi_n.Divide((BigInteger)smallPrimes[i]), n).Equals(BigInteger.One))
					{
						if (debug)
						{
							Console.WriteLine("g has order phi(n)/" + smallPrimes[i] + "\n g: " + g);
						}
						divisible = true;
						break;
					}
				}

				if (divisible)
				{
					continue;
				}

				// make sure that g has order > phi_n/4

				//if (g.ModPow(phi_n.Divide(BigInteger.ValueOf(4)), n).Equals(BigInteger.One))
				if (g.ModPow(phi_n.ShiftRight(2), n).Equals(BigInteger.One))
				{
					if (debug)
					{
						Console.WriteLine("g has order phi(n)/4\n g:" + g);
					}
					continue;
				}

				if (g.ModPow(phi_n.Divide(_p), n).Equals(BigInteger.One))
				{
					if (debug)
					{
						Console.WriteLine("g has order phi(n)/p'\n g: " + g);
					}
					continue;
				}
				if (g.ModPow(phi_n.Divide(_q), n).Equals(BigInteger.One))
				{
					if (debug)
					{
						Console.WriteLine("g has order phi(n)/q'\n g: " + g);
					}
					continue;
				}
				if (g.ModPow(phi_n.Divide(a), n).Equals(BigInteger.One))
				{
					if (debug)
					{
						Console.WriteLine("g has order phi(n)/a\n g: " + g);
					}
					continue;
				}
				if (g.ModPow(phi_n.Divide(b), n).Equals(BigInteger.One))
				{
					if (debug)
					{
						Console.WriteLine("g has order phi(n)/b\n g: " + g);
					}
					continue;
				}
				break;
			}
			if (debug)
			{
				Console.WriteLine("needed " + tries + " tries to generate g");
				Console.WriteLine();
				Console.WriteLine("found new NaccacheStern cipher variables:");
				Console.WriteLine("smallPrimes: " + CollectionUtilities.ToString(smallPrimes));
				Console.WriteLine("sigma:...... " + sigma + " (" + sigma.BitLength + " bits)");
				Console.WriteLine("a:.......... " + a);
				Console.WriteLine("b:.......... " + b);
				Console.WriteLine("p':......... " + _p);
				Console.WriteLine("q':......... " + _q);
				Console.WriteLine("p:.......... " + p);
				Console.WriteLine("q:.......... " + q);
				Console.WriteLine("n:.......... " + n);
				Console.WriteLine("phi(n):..... " + phi_n);
				Console.WriteLine("g:.......... " + g);
				Console.WriteLine();
			}

			return new AsymmetricCipherKeyPair(new NaccacheSternKeyParameters(false, g, n, sigma.BitLength),
				new NaccacheSternPrivateKeyParameters(g, n, sigma.BitLength, smallPrimes, phi_n));
		}

        private static IBigInteger GeneratePrime(
			int bitLength,
			int certainty,
			ISecureRandom rand)
		{
			return new BigInteger(bitLength, certainty, rand);
		}

		/**
		 * Generates a permuted ArrayList from the original one. The original List
		 * is not modified
		 *
		 * @param arr
		 *            the ArrayList to be permuted
		 * @param rand
		 *            the source of Randomness for permutation
		 * @return a new ArrayList with the permuted elements.
		 */
		private static IList PermuteList(
			IList           arr,
			ISecureRandom    rand)
		{
            // TODO Create a utility method for generating permutation of first 'n' integers

            IList retval = Platform.CreateArrayList(arr.Count);

			foreach (object element in arr)
			{
				int index = rand.Next(retval.Count + 1);
				retval.Insert(index, element);
			}

			return retval;
		}

		/**
		 * Finds the first 'count' primes starting with 3
		 *
		 * @param count
		 *            the number of primes to find
		 * @return a vector containing the found primes as Integer
		 */
		private static IList findFirstPrimes(
			int count)
		{
			IList primes = Platform.CreateArrayList(count);

			for (int i = 0; i != count; i++)
			{
				primes.Add(BigInteger.ValueOf(smallPrimes[i]));
			}

			return primes;
		}

	}
}

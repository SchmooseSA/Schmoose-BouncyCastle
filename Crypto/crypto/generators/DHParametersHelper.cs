using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    internal class DHParametersHelper
    {
        // The primes b/w 2 and ~2^10
        /*
                3   5   7   11  13  17  19  23  29
            31  37  41  43  47  53  59  61  67  71
            73  79  83  89  97  101 103 107 109 113
            127 131 137 139 149 151 157 163 167 173
            179 181 191 193 197 199 211 223 227 229
            233 239 241 251 257 263 269 271 277 281
            283 293 307 311 313 317 331 337 347 349
            353 359 367 373 379 383 389 397 401 409
            419 421 431 433 439 443 449 457 461 463
            467 479 487 491 499 503 509 521 523 541
            547 557 563 569 571 577 587 593 599 601
            607 613 617 619 631 641 643 647 653 659
            661 673 677 683 691 701 709 719 727 733
            739 743 751 757 761 769 773 787 797 809
            811 821 823 827 829 839 853 857 859 863
            877 881 883 887 907 911 919 929 937 941
            947 953 967 971 977 983 991 997
            1009 1013 1019 1021 1031
        */

        // Each list has a product < 2^31
        private static readonly int[][] _primeLists = new[]
        {
			new[]{ 3, 5, 7, 11, 13, 17, 19, 23 },
			new[]{ 29, 31, 37, 41, 43 },
			new[]{ 47, 53, 59, 61, 67 },
			new[]{ 71, 73, 79, 83 },
			new[]{ 89, 97, 101, 103 },

			new[]{ 107, 109, 113, 127 },
			new[]{ 131, 137, 139, 149 },
			new[]{ 151, 157, 163, 167 },
			new[]{ 173, 179, 181, 191 },
			new[]{ 193, 197, 199, 211 },

			new[]{ 223, 227, 229 },
			new[]{ 233, 239, 241 },
			new[]{ 251, 257, 263 },
			new[]{ 269, 271, 277 },
			new[]{ 281, 283, 293 },

			new[]{ 307, 311, 313 },
			new[]{ 317, 331, 337 },
			new[]{ 347, 349, 353 },
			new[]{ 359, 367, 373 },
			new[]{ 379, 383, 389 },

			new[]{ 397, 401, 409 },
			new[]{ 419, 421, 431 },
			new[]{ 433, 439, 443 },
			new[]{ 449, 457, 461 },
			new[]{ 463, 467, 479 },

			new[]{ 487, 491, 499 },
			new[]{ 503, 509, 521 },
			new[]{ 523, 541, 547 },
			new[]{ 557, 563, 569 },
			new[]{ 571, 577, 587 },

			new[]{ 593, 599, 601 },
			new[]{ 607, 613, 617 },
			new[]{ 619, 631, 641 },
			new[]{ 643, 647, 653 },
			new[]{ 659, 661, 673 },

			new[]{ 677, 683, 691 },
			new[]{ 701, 709, 719 },
			new[]{ 727, 733, 739 },
			new[]{ 743, 751, 757 },
			new[]{ 761, 769, 773 },

			new[]{ 787, 797, 809 },
			new[]{ 811, 821, 823 },
			new[]{ 827, 829, 839 },
			new[]{ 853, 857, 859 },
			new[]{ 863, 877, 881 },

			new[]{ 883, 887, 907 },
			new[]{ 911, 919, 929 },
			new[]{ 937, 941, 947 },
			new[]{ 953, 967, 971 },
			new[]{ 977, 983, 991 },

			new[]{ 997, 1009, 1013 },
			new[]{ 1019, 1021, 1031 }
		};

        private static readonly IBigInteger _six = BigInteger.ValueOf(6);

        private static readonly int[] _primeProductsInts;
        private static readonly IBigInteger[] _primeProductsBigs;

        static DHParametersHelper()
        {
            _primeProductsInts = new int[_primeLists.Length];
            _primeProductsBigs = new IBigInteger[_primeLists.Length];

            for (var i = 0; i < _primeLists.Length; ++i)
            {
                var primeList = _primeLists[i];
                var product = 1;
                for (var j = 0; j < primeList.Length; ++j)
                {
                    product *= primeList[j];
                }
                _primeProductsInts[i] = product;
                _primeProductsBigs[i] = BigInteger.ValueOf(product);
            }
        }

        /// <summary>
        /// Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
        /// 
        /// (see: Handbook of Applied Cryptography 4.86)
        /// </summary>
        /// <param name="size">The size.</param>
        /// <param name="certainty">The certainty.</param>
        /// <param name="random">The random.</param>
        /// <returns></returns>
        internal static IBigInteger[] GenerateSafePrimes(int size, int certainty, ISecureRandom random)
        {
            IBigInteger p, q;
            var qLength = size - 1;

            if (size <= 32)
            {
                for (; ; )
                {
                    q = new BigInteger(qLength, 2, random);

                    p = q.ShiftLeft(1).Add(BigInteger.One);

                    if (p.IsProbablePrime(certainty)
                        && (certainty <= 2 || q.IsProbablePrime(certainty)))
                        break;
                }
            }
            else
            {
                // Note: Modified from Java version for speed
                for (; ; )
                {
                    q = new BigInteger(qLength, 0, random);

                retry:
                    for (var i = 0; i < _primeLists.Length; ++i)
                    {
                        var test = q.Remainder(_primeProductsBigs[i]).IntValue;

                        if (i == 0)
                        {
                            var rem3 = test % 3;
                            if (rem3 != 2)
                            {
                                var diff = 2 * rem3 + 2;
                                q = q.Add(BigInteger.ValueOf(diff));
                                test = (test + diff) % _primeProductsInts[i];
                            }
                        }

                        var primeList = _primeLists[i];
                        foreach (var prime in primeList)
                        {
                            var qRem = test % prime;
                            if (qRem != 0 && qRem != (prime >> 1))
                                continue;

                            q = q.Add(_six);
                            goto retry;
                        }
                    }


                    if (q.BitLength != qLength)
                        continue;

                    if (!((BigInteger)q).RabinMillerTest(2, random))
                        continue;

                    p = q.ShiftLeft(1).Add(BigInteger.One);

                    if (((BigInteger)p).RabinMillerTest(certainty, random)
                        && (certainty <= 2 || ((BigInteger)q).RabinMillerTest(certainty - 2, random)))
                        break;
                }
            }

            return new[] { p, q };
        }

        /// <summary>
        /// Select a high order element of the multiplicative group Z
        ///
        /// p and q must be s.t. p = 2*q + 1, where p and q are prime (see generateSafePrimes)
        /// </summary>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="random">The random.</param>
        /// <returns></returns>
        internal static IBigInteger SelectGenerator(IBigInteger p, IBigInteger q, SecureRandom random)
        {
            var pMinusTwo = p.Subtract(BigInteger.Two);
            IBigInteger g;

            /*
             * (see: Handbook of Applied Cryptography 4.80)
             */
            //			do
            //			{
            //				g = BigIntegers.CreateRandomInRange(BigInteger.Two, pMinusTwo, random);
            //			}
            //			while (g.ModPow(BigInteger.Two, p).Equals(BigInteger.One)
            //				|| g.ModPow(q, p).Equals(BigInteger.One));

            /*
             * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
             */
            do
            {
                var h = BigIntegers.CreateRandomInRange(BigInteger.Two, pMinusTwo, random);

                g = h.ModPow(BigInteger.Two, p);
            }
            while (g.Equals(BigInteger.One));

            return g;
        }
    }
}

using NUnit.Framework;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Prng;

namespace Org.BouncyCastle.Security.Tests
{
    [TestFixture]
    public class SecureRandomTest
    {
#if !NETCF_1_0
        [Test]
        public void TestCryptoApi()
        {
            var random = new SecureRandom(new CryptoApiRandomGenerator());

            CheckSecureRandom(random);
        }
#endif

        [Test]
        public void TestDefault()
        {
            var random = new SecureRandom();

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSha1Prng()
        {
            var random = SecureRandom.GetInstance("SHA1PRNG");
            random.SetSeed(SecureRandom.GetSeed(20));

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSha256Prng()
        {
            var random = SecureRandom.GetInstance("SHA256PRNG");
            random.SetSeed(SecureRandom.GetSeed(32));

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSha512Prng()
        {
#if SUPPORT_SECURERND512

            var random = SecureRandom.GetInstance("SHA512PRNG");
            random.SetSeed(SecureRandom.GetSeed(64));

            CheckSecureRandom(random);
#endif
        }


        [Test]
        public void TestThreadedSeed()
        {
            var random = new SecureRandom(new ThreadedSeedGenerator().GenerateSeed(20, false));

            CheckSecureRandom(random);
        }

        [Test]
        public void TestVmpcPrng()
        {
            var random = new SecureRandom(new VmpcRandomGenerator());
            random.SetSeed(SecureRandom.GetSeed(32));

            CheckSecureRandom(random);
        }


        private static void CheckSecureRandom(SecureRandom random)
        {
            // Note: This will periodically (< 1e-6 probability) give a false alarm.
            // That's randomness for you!
            Assert.IsTrue(RunChiSquaredTests(random), "Chi2 test detected possible non-randomness");
        }

        private static bool RunChiSquaredTests(SecureRandom random)
        {
            var passes = 0;

            for (var tries = 0; tries < 100; ++tries)
            {
                var chi2 = MeasureChiSquared(random, 1000);
                if (chi2 < 285.0) // 255 degrees of freedom in test => Q ~ 10.0% for 285
                    ++passes;
            }

            return passes > 75;
        }

        private static double MeasureChiSquared(IRandom random, int rounds)
        {
            var counts = new int[256];

            var bs = new byte[256];
            for (var i = 0; i < rounds; ++i)
            {
                random.NextBytes(bs);

                for (var b = 0; b < 256; ++b)
                {
                    ++counts[bs[b]];
                }
            }

            var mask = SecureRandom.GetSeed(1)[0];
            for (var i = 0; i < rounds; ++i)
            {
                random.NextBytes(bs);

                for (var b = 0; b < 256; ++b)
                {
                    ++counts[bs[b] ^ mask];
                }

                ++mask;
            }

            var shift = SecureRandom.GetSeed(1)[0];
            for (var i = 0; i < rounds; ++i)
            {
                random.NextBytes(bs);

                for (var b = 0; b < 256; ++b)
                {
                    ++counts[(byte)(bs[b] + shift)];
                }

                ++shift;
            }

            var total = 3 * rounds;

            double chi2 = 0;
            for (var k = 0; k < counts.Length; ++k)
            {
                var diff = ((double)counts[k]) - total;
                var diff2 = diff * diff;

                chi2 += diff2;
            }

            chi2 /= total;

            return chi2;
        }
    }
}

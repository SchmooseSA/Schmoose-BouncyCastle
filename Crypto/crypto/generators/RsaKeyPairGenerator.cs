using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * an RSA key pair generator.
     */
    public class RsaKeyPairGenerator
		: IAsymmetricCipherKeyPairGenerator
    {
		private static readonly IBigInteger _defaultPublicExponent = BigInteger.ValueOf(0x10001);
		private const int DefaultTests = 12;

		private RsaKeyGenerationParameters _param;

		public void Init( IKeyGenerationParameters parameters)
		{
		    _param = parameters as RsaKeyGenerationParameters ??
		             new RsaKeyGenerationParameters(_defaultPublicExponent, parameters.Random, parameters.Strength, DefaultTests);
		}

        public IAsymmetricCipherKeyPair GenerateKeyPair()
        {
            IBigInteger p, q, n, phi;

            //
            // p and q values should have a length of half the strength in bits
            //
			var strength = _param.Strength;
            var pbitlength = (strength + 1) / 2;
            var qbitlength = (strength - pbitlength);
			var mindiffbits = strength / 3;

			var e = _param.PublicExponent;

			// TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
			// (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")

			//
            // Generate p, prime and (p-1) relatively prime to e
            //
            for (;;)
            {
				p = new BigInteger(pbitlength, 1, _param.Random);

				if (p.Mod(e).Equals(BigInteger.One))
					continue;

				if (!p.IsProbablePrime(_param.Certainty))
					continue;

				if (e.Gcd(p.Subtract(BigInteger.One)).Equals(BigInteger.One)) 
					break;
			}

            //
            // Generate a modulus of the required length
            //
            for (;;)
            {
                // Generate q, prime and (q-1) relatively prime to e,
                // and not equal to p
                //
                for (;;)
                {
					q = new BigInteger(qbitlength, 1, _param.Random);

					if (q.Subtract(p).Abs().BitLength < mindiffbits)
						continue;

					if (q.Mod(e).Equals(BigInteger.One))
						continue;

					if (!q.IsProbablePrime(_param.Certainty))
						continue;

					if (e.Gcd(q.Subtract(BigInteger.One)).Equals(BigInteger.One)) 
						break;
				}

                //
                // calculate the modulus
                //
                n = p.Multiply(q);

                if (n.BitLength == _param.Strength)
					break;

                //
                // if we Get here our primes aren't big enough, make the largest
                // of the two p and try again
                //
                p = p.Max(q);
            }

			if (p.CompareTo(q) < 0)
			{
				phi = p;
				p = q;
				q = phi;
			}

            var pSub1 = p.Subtract(BigInteger.One);
            var qSub1 = q.Subtract(BigInteger.One);
            phi = pSub1.Multiply(qSub1);

            //
            // calculate the private exponent
            //
            var d = e.ModInverse(phi);

            //
            // calculate the CRT factors
            //

            var dP = d.Remainder(pSub1);
            var dQ = d.Remainder(qSub1);
            var qInv = q.ModInverse(p);

            return new AsymmetricCipherKeyPair(
                new RsaKeyParameters(false, n, e),
                new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
        }
    }

}

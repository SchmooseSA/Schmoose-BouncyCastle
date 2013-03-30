using System;
using System.Collections;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	/**
	 * Private key parameters for NaccacheStern cipher. For details on this cipher,
	 * please see
	 *
	 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	 */
	public class NaccacheSternPrivateKeyParameters : NaccacheSternKeyParameters
	{
		private readonly IBigInteger phiN;
		private readonly IList smallPrimes;

#if !SILVERLIGHT
        [Obsolete]
        public NaccacheSternPrivateKeyParameters(
            IBigInteger g,
            IBigInteger n,
            int lowerSigmaBound,
            ArrayList smallPrimes,
            IBigInteger phiN)
            : base(true, g, n, lowerSigmaBound)
        {
            this.smallPrimes = smallPrimes;
            this.phiN = phiN;
        }
#endif

		/**
		 * Constructs a NaccacheSternPrivateKey
		 *
		 * @param g
		 *            the public enryption parameter g
		 * @param n
		 *            the public modulus n = p*q
		 * @param lowerSigmaBound
		 *            the public lower sigma bound up to which data can be encrypted
		 * @param smallPrimes
		 *            the small primes, of which sigma is constructed in the right
		 *            order
		 * @param phi_n
		 *            the private modulus phi(n) = (p-1)(q-1)
		 */
		public NaccacheSternPrivateKeyParameters(
            IBigInteger g,
            IBigInteger n,
			int			lowerSigmaBound,
			IList       smallPrimes,
			IBigInteger	phiN)
			: base(true, g, n, lowerSigmaBound)
		{
			this.smallPrimes = smallPrimes;
			this.phiN = phiN;
		}

		public IBigInteger PhiN
		{
			get { return phiN; }
		}

#if !SILVERLIGHT
        [Obsolete("Use 'SmallPrimesList' instead")]
        public ArrayList SmallPrimes
		{
			get { return new ArrayList(smallPrimes); }
		}
#endif

        public IList SmallPrimesList
        {
            get { return smallPrimes; }
        }
    }
}

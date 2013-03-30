using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	/**
	 * Public key parameters for NaccacheStern cipher. For details on this cipher,
	 * please see
	 *
	 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	 */
	public class NaccacheSternKeyParameters : AsymmetricKeyParameter
	{
        private readonly IBigInteger g, n;
		private readonly int lowerSigmaBound;

		/**
		 * @param privateKey
		 */
        public NaccacheSternKeyParameters(bool privateKey, IBigInteger g, IBigInteger n, int lowerSigmaBound)
			: base(privateKey)
		{
			this.g = g;
			this.n = n;
			this.lowerSigmaBound = lowerSigmaBound;
		}

		/**
		 * @return Returns the g.
		 */
        public IBigInteger G { get { return g; } }

		/**
		 * @return Returns the lowerSigmaBound.
		 */
		public int LowerSigmaBound { get { return lowerSigmaBound; } }

		/**
		 * @return Returns the n.
		 */
        public IBigInteger Modulus { get { return n; } }
	}
}

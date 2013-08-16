using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ElGamalParameters
		: ICipherParameters
    {
        private readonly IBigInteger p, g;
		private readonly int l;

		public ElGamalParameters(
            IBigInteger	p,
            IBigInteger	g)
			: this(p, g, 0)
        {
        }

		public ElGamalParameters(
			IBigInteger	p,
			IBigInteger	g,
			int			l)
		{
			if (p == null)
				throw new ArgumentNullException("p");
			if (g == null)
				throw new ArgumentNullException("g");

			this.p = p;
			this.g = g;
			this.l = l;
		}

		public IBigInteger P
        {
            get { return p; }
        }

		/**
        * return the generator - g
        */
        public IBigInteger G
        {
            get { return g; }
        }

		/**
		 * return private value limit - l
		 */
		public int L
		{
			get { return l; }
		}

		public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			ElGamalParameters other = obj as ElGamalParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			ElGamalParameters other)
		{
			return p.Equals(other.p) && g.Equals(other.g) && l == other.l;
		}

		public override int GetHashCode()
        {
            return p.GetHashCode() ^ g.GetHashCode() ^ l;
        }
    }
}

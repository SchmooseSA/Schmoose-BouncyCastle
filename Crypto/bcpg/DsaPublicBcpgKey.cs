using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Base class for a DSA public key.</remarks>
    public class DsaPublicBcpgKey : BcpgObject, IBcpgPublicKey
    {
        private readonly MPInteger _p, _q, _g, _y;

		/// <param name="bcpgIn">The stream to read the packet from.</param>
		public DsaPublicBcpgKey(BcpgInputStream bcpgIn)
		{
			_p = new MPInteger(bcpgIn);
			_q = new MPInteger(bcpgIn);
			_g = new MPInteger(bcpgIn);
			_y = new MPInteger(bcpgIn);
		}

		public DsaPublicBcpgKey(IBigInteger p, IBigInteger q, IBigInteger g, IBigInteger y)
		{
			_p = new MPInteger(p);
			_q = new MPInteger(q);
			_g = new MPInteger(g);
			_y = new MPInteger(y);
		}

        /// <summary>
        /// Gets the bit strength.
        /// </summary>
        /// <value>
        /// The bit strength.
        /// </value>
	    public int BitStrength 
        {
            get { return this.P.BitLength; }
        }

	    /// <summary>The format, as a string, always "PGP".</summary>
		public string Format
		{
			get { return "PGP"; }
		}

		public override void Encode(IBcpgOutputStream bcpgOut)
		{
			bcpgOut.WriteObjects(_p, _q, _g, _y);
		}

        public IBigInteger G
		{
			get { return _g.Value; }
		}

        public IBigInteger P
		{
			get { return _p.Value; }
		}

        public IBigInteger Q
		{
			get { return _q.Value; }
		}

        public IBigInteger Y
		{
			get { return _y.Value; }
		}
    }
}

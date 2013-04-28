using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Base class for an ElGamal public key.</remarks>
	public class ElGamalPublicBcpgKey : BcpgObject, IBcpgKey
	{
		private readonly MPInteger _p, _g, _y;

		public ElGamalPublicBcpgKey(BcpgInputStream bcpgIn)
		{
			_p = new MPInteger(bcpgIn);
			_g = new MPInteger(bcpgIn);
			_y = new MPInteger(bcpgIn);
		}

		public ElGamalPublicBcpgKey(IBigInteger p, IBigInteger g, IBigInteger y)
		{
			_p = new MPInteger(p);
			_g = new MPInteger(g);
			_y = new MPInteger(y);
		}

		/// <summary>The format, as a string, always "PGP".</summary>
		public string Format
		{
			get { return "PGP"; }
		}		

        public IBigInteger P
		{
			get { return _p.Value; }
		}

        public IBigInteger G
		{
			get { return _g.Value; }
		}

        public IBigInteger Y
		{
			get { return _y.Value; }
		}

		public override void Encode(IBcpgOutputStream bcpgOut)
		{
			bcpgOut.WriteObjects(_p, _g, _y);
		}
	}
}

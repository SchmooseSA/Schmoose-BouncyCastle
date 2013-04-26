using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Base class for an ElGamal public key.</remarks>
	public class ElGamalPublicBcpgKey : BcpgObject, IBcpgKey
	{
		internal MPInteger p, g, y;

		public ElGamalPublicBcpgKey(BcpgInputStream bcpgIn)
		{
			this.p = new MPInteger(bcpgIn);
			this.g = new MPInteger(bcpgIn);
			this.y = new MPInteger(bcpgIn);
		}

		public ElGamalPublicBcpgKey(
			IBigInteger p,
			IBigInteger g,
			IBigInteger y)
		{
			this.p = new MPInteger(p);
			this.g = new MPInteger(g);
			this.y = new MPInteger(y);
		}

		/// <summary>The format, as a string, always "PGP".</summary>
		public string Format
		{
			get { return "PGP"; }
		}

		/// <summary>Return the standard PGP encoding of the key.</summary>
		public override byte[] GetEncoded()
		{
			try
			{
				return base.GetEncoded();
			}
			catch (Exception)
			{
				return null;
			}
		}

        public IBigInteger P
		{
			get { return p.Value; }
		}

        public IBigInteger G
		{
			get { return g.Value; }
		}

        public IBigInteger Y
		{
			get { return y.Value; }
		}

		public override void Encode(
			IBcpgOutputStream bcpgOut)
		{
			bcpgOut.WriteObjects(p, g, y);
		}
	}
}

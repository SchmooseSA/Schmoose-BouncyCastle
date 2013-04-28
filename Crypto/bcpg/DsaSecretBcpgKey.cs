using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Base class for a DSA secret key.</remarks>
	public class DsaSecretBcpgKey : BcpgObject, IBcpgKey
    {
		private readonly MPInteger _x;

		/**
		* @param in
		*/
		public DsaSecretBcpgKey(BcpgInputStream bcpgIn)
		{
            _x = new MPInteger(bcpgIn);
		}

		public DsaSecretBcpgKey(IBigInteger x)
		{
            _x = new MPInteger(x);
		}

		/// <summary>The format, as a string, always "PGP".</summary>
		public string Format
		{
			get { return "PGP"; }
		}
		
		public override void Encode(IBcpgOutputStream bcpgOut)
		{
			bcpgOut.WriteObject(_x);
		}

		/**
		* @return x
		*/
        public IBigInteger X
		{
			get { return _x.Value; }
		}
	}
}

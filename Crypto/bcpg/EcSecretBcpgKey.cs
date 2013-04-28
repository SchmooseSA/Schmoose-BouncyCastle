using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    public class EcSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private readonly MPInteger _x;

        public EcSecretBcpgKey(BcpgInputStream bcpgIn)
		{
            _x = new MPInteger(bcpgIn);
		}

        public EcSecretBcpgKey(IBigInteger x)
		{
            _x = new MPInteger(x);
		}

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteObject(_x);
        }

        public string Format
        {
            get { return "PGP"; }
        }

        /// <summary>
        /// Gets the X.
        /// </summary>
        /// <value>
        /// The X.
        /// </value>
        public IBigInteger X
        {
            get { return _x.Value; }
        }
    }
}

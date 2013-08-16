using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    public class ECSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private readonly MPInteger _x;

        public ECSecretBcpgKey(BcpgInputStream bcpgIn)
		{
            _x = new MPInteger(bcpgIn);
		}

        public ECSecretBcpgKey(IBigInteger x)
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

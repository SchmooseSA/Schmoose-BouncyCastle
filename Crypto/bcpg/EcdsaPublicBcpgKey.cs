using System;

namespace Org.BouncyCastle.Bcpg
{
    public class EcdsaPublicBcpgKey : EcPublicBcpgKey
    {        
        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaPublicBcpgKey"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        public EcdsaPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn) { }

        /// <summary>
        /// Encodes the specified BCPG out.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        /// <exception cref="System.NotImplementedException"></exception>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            throw new NotImplementedException();
        }                       
    }
}

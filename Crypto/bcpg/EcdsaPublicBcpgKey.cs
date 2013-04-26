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
    }
}

namespace Org.BouncyCastle.Bcpg
{
    public interface IBcpgPublicKey : IBcpgKey
    {
        /// <summary>
        /// Gets the bit strength.
        /// </summary>
        /// <value>
        /// The bit strength.
        /// </value>
        int BitStrength { get; }
    }
}

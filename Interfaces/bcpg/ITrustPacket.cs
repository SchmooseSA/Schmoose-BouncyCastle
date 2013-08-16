namespace Org.BouncyCastle.Bcpg
{
    public interface ITrustPacket : IContainedPacket
    {
        /// <summary>
        /// Gets the level and trust amount.
        /// </summary>
        /// <returns></returns>
        byte[] GetLevelAndTrustAmount();
    }
}
namespace Org.BouncyCastle.Bcpg.Attr
{
    public interface IImageAttribute : IUserAttributeSubpacket
    {
        int Version { get; }
        int Encoding { get; }
        byte[] GetImageData();
    }
}
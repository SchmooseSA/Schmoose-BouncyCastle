namespace Org.BouncyCastle.Bcpg.Attr
{
    public interface IImageAttrib : IUserAttributeSubpacket
    {
        int Version { get; }
        int Encoding { get; }
        byte[] GetImageData();
    }
}
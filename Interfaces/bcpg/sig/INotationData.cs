namespace Org.BouncyCastle.Bcpg.Sig
{
    public interface INotationData : ISignatureSubpacket
    {
        bool IsHumanReadable { get; }
        
        string GetNotationName();
        
        string GetNotationValue();

        byte[] GetNotationValueBytes();
    }
}
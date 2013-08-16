using System;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpSignatureSubpacketVector
    {
        ISignatureSubpacket GetSubpacket(SignatureSubpacketTag type);
        bool HasSubpacket(SignatureSubpacketTag type);
        ISignatureSubpacket[] GetSubpackets(SignatureSubpacketTag type);
        INotationData[] GetNotationDataOccurences();
        long GetIssuerKeyId();
        bool HasSignatureCreationTime();
        DateTime GetSignatureCreationTime();

        /// <summary>
        /// Return the number of seconds a signature is valid for after its creation date.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        long GetSignatureExpirationTime();

        /// <summary>
        /// Return the number of seconds a key is valid for after its creation date.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        long GetKeyExpirationTime();

        int[] GetPreferredHashAlgorithms();
        int[] GetPreferredSymmetricAlgorithms();
        int[] GetPreferredCompressionAlgorithms();
        int GetKeyFlags();
        string GetSignerUserId();
        bool IsPrimaryUserId();
        SignatureSubpacketTag[] GetCriticalTags();

        [Obsolete("Use 'Count' property instead")]
        int Size { get; }

        /// <summary>Return the number of packets this vector contains.</summary>
        int Count { get; }

        ISignatureSubpacket[] ToSubpacketArray();
    }
}
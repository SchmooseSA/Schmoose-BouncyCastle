using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Base class for a PGP object.</remarks>
    public abstract class BcpgObject : IBcpgObject
	{
        public virtual byte[] GetEncoded()
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                using (BcpgOutputStream pOut = new BcpgOutputStream(bOut))
                {

                    pOut.WriteObject(this);

                    return bOut.ToArray();
                }
            }
        }

		public abstract void Encode(IBcpgOutputStream bcpgOut);
    }
}


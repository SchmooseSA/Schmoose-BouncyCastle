using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Base class for a PGP object.</remarks>
    public abstract class BcpgObject : IBcpgObject
	{
        public byte[] GetEncoded()
        {
            try
            {
                using (var bOut = new MemoryStream())
                {
                    using (var pOut = new BcpgOutputStream(bOut))
                    {
                        pOut.WriteObject(this);
                        return bOut.ToArray();
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }            
        }

		public abstract void Encode(IBcpgOutputStream bcpgOut);
    }
}


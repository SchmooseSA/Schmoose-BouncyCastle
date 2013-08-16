using System.IO;

using Org.BouncyCastle.Asn1.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class WrappedGeneratorStream : FilterStream
    {
        private IStreamGenerator _gen;

        public WrappedGeneratorStream(IStreamGenerator gen, Stream str)
            : base(str)
        {
            _gen = gen;
        }
#if !NETFX_CORE
		public override void Close()
		{
			_gen.Close();
		}
#else
        protected override void Dispose(bool disposing)
        {
            try
            {
                _gen.Close();
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
#endif
    }
}

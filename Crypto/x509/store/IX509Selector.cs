using System;

namespace Org.BouncyCastle.X509.Store
{
	public interface IX509Selector
#if !(SILVERLIGHT || NETFX_CORE)
		: ICloneable
#endif
    {
#if SILVERLIGHT || NETFX_CORE
        object Clone();
#endif
        bool Match(object obj);
	}
}

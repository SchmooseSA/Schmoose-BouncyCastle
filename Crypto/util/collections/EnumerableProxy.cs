using System;
using System.Collections;

namespace Org.BouncyCastle.Utilities.Collections
{
	public sealed class EnumerableProxy : IEnumerable
	{
		private readonly IEnumerable _inner;

		public EnumerableProxy(IEnumerable inner)
		{
			if (inner == null)
				throw new ArgumentNullException("inner");

			_inner = inner;
		}

		public IEnumerator GetEnumerator()
		{
			return _inner.GetEnumerator();
		}
	}
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Utilities.Collections
{
    public static class CollectionUtilities
    {
        public static void AddRange(IList to, ICollection range)
        {
            foreach (var o in range)
            {
                to.Add(o);
            }
        }

        public static void AddRange<T>(IList<T> to, ICollection<T> range)
        {
            foreach (var o in range)
            {
                to.Add(o);
            }
        }

        public static bool CheckElementsAreOfType(IEnumerable e, Type t)
        {
            return e.Cast<object>().All(t.IsInstanceOfType);
        }

        public static IDictionary ReadOnly(IDictionary d)
        {
            return new UnmodifiableDictionaryProxy(d);
        }

        public static IList ReadOnly(IList l)
        {
            return new UnmodifiableListProxy(l);
        }

        public static ISet ReadOnly(ISet s)
        {
            return new UnmodifiableSetProxy(s);
        }

        public static string ToString(IEnumerable c)
        {
            var sb = new StringBuilder("[");

            var e = c.GetEnumerator();

            if (e.MoveNext())
            {
                sb.Append(e.Current);

                while (e.MoveNext())
                {
                    sb.Append(", ");
                    sb.Append(e.Current);
                }
            }

            sb.Append(']');

            return sb.ToString();
        }
    }
}

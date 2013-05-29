using System;
using System.Collections.Generic;
using System.Threading;

#if SILVERLIGHT
#else
using System.Collections;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading;

#endif

namespace Org.BouncyCastle.Utilities
{
    internal static class Platform
    {
#if NETCF_1_0 || NETCF_2_0
		private static string GetNewLine()
		{
			MemoryStream buf = new MemoryStream();
			StreamWriter w = new StreamWriter(buf, Encoding.UTF8);
			w.WriteLine();
			w.Close();
			byte[] bs = buf.ToArray();
            return Encoding.UTF8.GetString(bs, 0, bs.Length);
		}
#else
        private static string GetNewLine()
        {
            return Environment.NewLine;
        }
#endif

        internal static int CompareIgnoreCase(string a, string b)
        {
#if SILVERLIGHT
            return String.Compare(a, b, StringComparison.InvariantCultureIgnoreCase);
#else
            return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
#endif
        }

#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || NETFX_CORE
        internal static string GetEnvironmentVariable(
            string variable)
        {
            return null;
        }
#else
		internal static string GetEnvironmentVariable(
			string variable)
		{
			try
			{
				return Environment.GetEnvironmentVariable(variable);
			}
			catch (System.Security.SecurityException)
			{
				// We don't have the required permission to read this environment variable,
				// which is fine, just act as if it's not set
				return null;
			}
		}
#endif

#if NETCF_1_0
		internal static Exception CreateNotImplementedException(
			string message)
		{
			return new Exception("Not implemented: " + message);
		}

		internal static bool Equals(
			object	a,
			object	b)
		{
			return a == b || (a != null && b != null && a.Equals(b));
		}
#else
        internal static Exception CreateNotImplementedException(
            string message)
        {
            return new NotImplementedException(message);
        }
#endif

#if SILVERLIGHT || NETFX_CORE
        internal static System.Collections.IList CreateArrayList()
        {
            return new List<object>();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new List<object>(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            System.Collections.IList result = new List<object>(collection.Count);
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            System.Collections.IList result = new List<object>();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Dictionary<object, object>();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Dictionary<object, object>(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            System.Collections.IDictionary result = new Dictionary<object, object>(dictionary.Count);
            foreach (System.Collections.DictionaryEntry entry in dictionary)
            {
                result.Add(entry.Key, entry.Value);
            }
            return result;
        }

        internal static string StringToLower(string s)
        {
            return s.ToLowerInvariant();
        }

        internal static string StringToUpper(string s)
        {
            return s.ToUpperInvariant();
        }
#else
        internal static System.Collections.IList CreateArrayList()
        {
            return new ArrayList();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new ArrayList(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            return new ArrayList(collection);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            var result = new ArrayList();
            foreach (var o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Hashtable();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Hashtable(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            return new Hashtable(dictionary);
        }

        internal static string StringToLower(string s)
        {
            return s.ToLower(CultureInfo.InvariantCulture);
        }

        internal static string StringToUpper(string s)
        {
            return s.ToUpper(CultureInfo.InvariantCulture);
        }
#endif

        internal static IList<T> CreateArrayList<T>()
        {
            return new List<T>();
        }

        internal static IList<T> CreateArrayList<T>(int capacity)
        {
            return new List<T>(capacity);
        }

        internal static IList<T> CreateArrayList<T>(IEnumerable<T> collection)
        {
            return new List<T>(collection);
        }

        internal static IDictionary<TKey, TValue> CreateHashtable<TKey, TValue>()
        {
            return new Dictionary<TKey, TValue>();
        }

        internal static IDictionary<TKey, TValue> CreateHashtable<TKey, TValue>(int capacity)
        {
            return new Dictionary<TKey, TValue>(capacity);
        }

        internal static IDictionary<TKey, TValue> CreateHashtable<TKey, TValue>(IDictionary<TKey, TValue> dictionary)
        {
            return new Dictionary<TKey, TValue>(dictionary);
        }

        internal static readonly string NewLine = GetNewLine();

#if NETFX_CORE
        internal static void ThreadSleep(int ms)
        {
            var ev = new ManualResetEvent(false);
            ev.WaitOne(ms);
        }
#else
        internal static void ThreadSleep(int ms)
        {
            Thread.Sleep(ms);
        }
#endif


#if NETFX_CORE
        public static bool IsInstanceOfType(this Type type, object o)
        {
            return o != null && type.IsInstanceOfType(o);
        }

        internal static bool ImplementInterface(this Type type, Type ifaceType)
        {
            while (type != null)
            {
                var interfaces = type.GetTypeInfo().ImplementedInterfaces.ToArray(); // .GetInterfaces();
                if (interfaces != null)
                {
                    if (interfaces.Any(t => t == ifaceType || (t != null && t.ImplementInterface(ifaceType))))
                    {
                        return true;
                    }
                }
                type = type.GetTypeInfo().BaseType;
                // type = type.BaseType;
            }
            return false;
        }

        public static bool IsAssignableFrom(this Type type, Type c)
        {
            if (c == null)
            {
                return false;
            }
            if (type == c)
            {
                return true;
            }

            //RuntimeType runtimeType = type.UnderlyingSystemType as RuntimeType;
            //if (runtimeType != null)
            //{
            // return runtimeType.IsAssignableFrom(c);
            //}

            //if (c.IsSubclassOf(type))
            if (c.GetTypeInfo().IsSubclassOf(c))
            {
                return true;
            }

            //if (type.IsInterface)
            if (type.GetTypeInfo().IsInterface)
            {
                return c.ImplementInterface(type);
            }

            if (type.IsGenericParameter)
            {
                var genericParameterConstraints = type.GetTypeInfo().GetGenericParameterConstraints();
                return genericParameterConstraints.All(t => t.IsAssignableFrom(c));
            }
            return false;
        }
#endif
    }
}

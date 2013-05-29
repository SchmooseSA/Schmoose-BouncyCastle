using System.Collections;
using System.Globalization;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.Nist
{
    /**
    * Utility class for fetching curves using their NIST names as published in FIPS-PUB 186-2
    */
    public static class NistNamedCurves
    {
        private static readonly IDictionary _objIds = Platform.CreateHashtable();
        private static readonly IDictionary _names = Platform.CreateHashtable();

        private static void DefineCurve(string name, DerObjectIdentifier oid)
        {
            _objIds.Add(name, oid);
            _names.Add(oid, name);
        }

        static NistNamedCurves()
        {
            DefineCurve("B-571", SecObjectIdentifiers.SecT571r1);
            DefineCurve("B-409", SecObjectIdentifiers.SecT409r1);
            DefineCurve("B-283", SecObjectIdentifiers.SecT283r1);
            DefineCurve("B-233", SecObjectIdentifiers.SecT233r1);
            DefineCurve("B-163", SecObjectIdentifiers.SecT163r2);
            DefineCurve("P-521", SecObjectIdentifiers.SecP521r1);
            DefineCurve("P-384", SecObjectIdentifiers.SecP384r1);
            DefineCurve("P-256", SecObjectIdentifiers.SecP256r1);
            DefineCurve("P-224", SecObjectIdentifiers.SecP224r1);
            DefineCurve("P-192", SecObjectIdentifiers.SecP192r1);
        }

        public static X9ECParameters GetByName(string name)
        {
            var oid = (DerObjectIdentifier)_objIds[Platform.StringToUpper(name)];
            return oid != null ? GetByOid(oid) : null;
        }

        /**
        * return the X9ECParameters object for the named curve represented by
        * the passed in object identifier. Null if the curve isn't present.
        *
        * @param oid an object identifier representing a named curve, if present.
        */
        public static X9ECParameters GetByOid(DerObjectIdentifier oid)
        {
            return SecNamedCurves.GetByOid(oid);
        }

        /**
        * return the object identifier signified by the passed in name. Null
        * if there is no object identifier associated with name.
        *
        * @return the object identifier associated with name, if present.
        */
        public static DerObjectIdentifier GetOid(string name)
        {
            return (DerObjectIdentifier)_objIds[Platform.StringToUpper(name)];
        }

        /**
        * return the named curve name represented by the given object identifier.
        */
        public static string GetName(DerObjectIdentifier oid)
        {
            return (string)_names[oid];
        }

        /**
        * returns an enumeration containing the name strings for curves
        * contained in this structure.
        */
        public static IEnumerable Names
        {
            get { return new EnumerableProxy(_objIds.Keys); }
        }
    }
}

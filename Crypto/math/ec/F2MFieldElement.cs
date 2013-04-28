using System;

namespace Org.BouncyCastle.Math.EC
{
    public class F2MFieldElement : ECFieldElement
    {
        /**
         * Indicates gaussian normal basis representation (GNB). Number chosen
         * according to X9.62. GNB is not implemented at present.
         */
        public const int Gnb = 1;

        /**
         * Indicates trinomial basis representation (Tpb). Number chosen
         * according to X9.62.
         */
        public const int Tpb = 2;

        /**
         * Indicates pentanomial basis representation (Ppb). Number chosen
         * according to X9.62.
         */
        public const int Ppb = 3;

        /**
         * Tpb or Ppb.
         */
        private readonly int _representation;

        /**
         * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
         */
        private readonly int _m;

        /**
         * Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br/>
         * Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int _k1;

        /**
         * Tpb: Always set to <code>0</code><br/>
         * Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int _k2;

        /**
            * Tpb: Always set to <code>0</code><br/>
            * Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        private readonly int _k3;

        /**
         * The <code>IntArray</code> holding the bits.
         */
        private readonly IntArray _x;

        /**
         * The number of <code>int</code>s required to hold <code>m</code> bits.
         */
        private readonly int _t;

        /**
            * Constructor for Ppb.
            * @param m  The exponent <code>m</code> of
            * <code>F<sub>2<sup>m</sup></sub></code>.
            * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.
            * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.
            * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.
            * @param x The IBigInteger representing the value of the field element.
            */
        public F2MFieldElement(int m, int k1, int k2, int k3, IBigInteger x)
        {
            // t = m / 32 rounded up to the next integer
            _t = (m + 31) >> 5;
            _x = new IntArray(x, _t);

            if ((k2 == 0) && (k3 == 0))
            {
                _representation = Tpb;
            }
            else
            {
                if (k2 >= k3)
                    throw new ArgumentException("k2 must be smaller than k3");
                if (k2 <= 0)
                    throw new ArgumentException("k2 must be larger than 0");

                _representation = Ppb;
            }

            if (x.SignValue < 0)
                throw new ArgumentException("x value cannot be negative");

            _m = m;
            _k1 = k1;
            _k2 = k2;
            _k3 = k3;
        }

        /**
            * Constructor for Tpb.
            * @param m  The exponent <code>m</code> of
            * <code>F<sub>2<sup>m</sup></sub></code>.
            * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
            * x<sup>k</sup> + 1</code> represents the reduction
            * polynomial <code>f(z)</code>.
            * @param x The IBigInteger representing the value of the field element.
            */
        public F2MFieldElement(int m, int k, IBigInteger x)
            : this(m, k, 0, 0, x)
        {
            // Set k1 to k, and set k2 and k3 to 0
        }

        private F2MFieldElement(int m, int k1, int k2, int k3, IntArray x)
        {
            _t = (m + 31) >> 5;
            _x = x;
            _m = m;
            _k1 = k1;
            _k2 = k2;
            _k3 = k3;

            if ((k2 == 0) && (k3 == 0))
            {
                _representation = Tpb;
            }
            else
            {
                _representation = Ppb;
            }
        }

        public override IBigInteger ToBigInteger()
        {
            return _x.ToBigInteger();
        }

        public override string FieldName
        {
            get { return "F2m"; }
        }

        public override int FieldSize
        {
            get { return _m; }
        }

        /**
        * Checks, if the ECFieldElements <code>a</code> and <code>b</code>
        * are elements of the same field <code>F<sub>2<sup>m</sup></sub></code>
        * (having the same representation).
        * @param a field element.
        * @param b field element to be compared.
        * @throws ArgumentException if <code>a</code> and <code>b</code>
        * are not elements of the same field
        * <code>F<sub>2<sup>m</sup></sub></code> (having the same
        * representation).
        */
        public static void CheckFieldElements(ECFieldElement a, ECFieldElement b)
        {
            if (!(a is F2MFieldElement) || !(b is F2MFieldElement))
            {
                throw new ArgumentException("Field elements are not "
                                            + "both instances of F2mFieldElement");
            }

            var aF2M = (F2MFieldElement)a;
            var bF2M = (F2MFieldElement)b;

            if ((aF2M._m != bF2M._m) || (aF2M._k1 != bF2M._k1) || (aF2M._k2 != bF2M._k2) || (aF2M._k3 != bF2M._k3))
            {
                throw new ArgumentException("Field elements are not "
                                            + "elements of the same field F2m");
            }

            if (aF2M._representation != bF2M._representation)
            {
                // Should never occur
                throw new ArgumentException(
                    "One of the field "
                    + "elements are not elements has incorrect representation");
            }
        }

        public override ECFieldElement Add(ECFieldElement b)
        {
            // No check performed here for performance reasons. Instead the
            // elements involved are checked in ECPoint.F2m
            // checkFieldElements(this, b);
            var iarrClone = _x.Copy();
            var bF2M = (F2MFieldElement)b;
            iarrClone.AddShifted(bF2M._x, 0);
            return new F2MFieldElement(_m, _k1, _k2, _k3, iarrClone);
        }

        public override ECFieldElement Subtract(ECFieldElement b)
        {
            // Addition and subtraction are the same in F2m
            return Add(b);
        }

        public override ECFieldElement Multiply(ECFieldElement b)
        {
            // Right-to-left comb multiplication in the IntArray
            // Input: Binary polynomials a(z) and b(z) of degree at most m-1
            // Output: c(z) = a(z) * b(z) mod f(z)

            // No check performed here for performance reasons. Instead the
            // elements involved are checked in ECPoint.F2m
            // checkFieldElements(this, b);
            var bF2M = (F2MFieldElement)b;
            var mult = _x.Multiply(bF2M._x, _m);
            mult.Reduce(_m, new[] { _k1, _k2, _k3 });
            return new F2MFieldElement(_m, _k1, _k2, _k3, mult);
        }

        public override ECFieldElement Divide(ECFieldElement b)
        {
            // There may be more efficient implementations
            var bInv = b.Invert();
            return Multiply(bInv);
        }

        public override ECFieldElement Negate()
        {
            // -x == x holds for all x in F2m
            return this;
        }

        public override ECFieldElement Square()
        {
            var squared = _x.Square(_m);
            squared.Reduce(_m, new[] { _k1, _k2, _k3 });
            return new F2MFieldElement(_m, _k1, _k2, _k3, squared);
        }

        public override ECFieldElement Invert()
        {
            // Inversion in F2m using the extended Euclidean algorithm
            // Input: A nonzero polynomial a(z) of degree at most m-1
            // Output: a(z)^(-1) mod f(z)

            // u(z) := a(z)
            var uz = _x.Copy();

            // v(z) := f(z)
            var vz = new IntArray(_t);
            vz.SetBit(_m);
            vz.SetBit(0);
            vz.SetBit(this._k1);
            if (this._representation == Ppb)
            {
                vz.SetBit(this._k2);
                vz.SetBit(this._k3);
            }

            // g1(z) := 1, g2(z) := 0
            var g1Z = new IntArray(_t);
            g1Z.SetBit(0);
            var g2Z = new IntArray(_t);

            // while u != 0
            while (uz.GetUsedLength() > 0)
            //            while (uz.bitLength() > 1)
            {
                // j := deg(u(z)) - deg(v(z))
                var j = uz.BitLength - vz.BitLength;

                // If j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
                if (j < 0)
                {
                    var uzCopy = uz;
                    uz = vz;
                    vz = uzCopy;

                    var g1ZCopy = g1Z;
                    g1Z = g2Z;
                    g2Z = g1ZCopy;

                    j = -j;
                }

                // u(z) := u(z) + z^j * v(z)
                // Note, that no reduction modulo f(z) is required, because
                // deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
                // = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
                // = deg(u(z))
                // uz = uz.xor(vz.ShiftLeft(j));
                // jInt = n / 32
                var jInt = j >> 5;
                // jInt = n % 32
                var jBit = j & 0x1F;
                var vzShift = vz.ShiftLeft(jBit);
                uz.AddShifted(vzShift, jInt);

                // g1(z) := g1(z) + z^j * g2(z)
                //                g1z = g1z.xor(g2z.ShiftLeft(j));
                var g2ZShift = g2Z.ShiftLeft(jBit);
                g1Z.AddShifted(g2ZShift, jInt);
            }
            return new F2MFieldElement(this._m, this._k1, this._k2, this._k3, g2Z);
        }

        public override ECFieldElement Sqrt()
        {
            throw new ArithmeticException("Not implemented");
        }

        /**
            * @return the representation of the field
            * <code>F<sub>2<sup>m</sup></sub></code>, either of
            * {@link F2mFieldElement.Tpb} (trinomial
            * basis representation) or
            * {@link F2mFieldElement.Ppb} (pentanomial
            * basis representation).
            */
        public int Representation
        {
            get { return _representation; }
        }

        /**
            * @return the degree <code>m</code> of the reduction polynomial
            * <code>f(z)</code>.
            */
        public int M
        {
            get { return _m; }
        }

        /**
            * @return Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
            * x<sup>k</sup> + 1</code> represents the reduction polynomial
            * <code>f(z)</code>.<br/>
            * Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        public int K1
        {
            get { return _k1; }
        }

        /**
            * @return Tpb: Always returns <code>0</code><br/>
            * Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        public int K2
        {
            get { return _k2; }
        }

        /**
            * @return Tpb: Always set to <code>0</code><br/>
            * Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        public int K3
        {
            get { return _k3; }
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var other = obj as F2MFieldElement;
            return other != null && Equals(other);
        }

        protected bool Equals(F2MFieldElement other)
        {
            return _m == other._m
                   && _k1 == other._k1
                   && _k2 == other._k2
                   && _k3 == other._k3
                   && _representation == other._representation
                   && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return _m.GetHashCode()
                   ^ _k1.GetHashCode()
                   ^ _k2.GetHashCode()
                   ^ _k3.GetHashCode()
                   ^ _representation.GetHashCode()
                   ^ base.GetHashCode();
        }
    }
}
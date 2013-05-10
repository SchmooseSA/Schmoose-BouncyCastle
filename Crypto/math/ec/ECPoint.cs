using System;
using System.Collections;
using System.Diagnostics;

using Org.BouncyCastle.Asn1.X9;

using Org.BouncyCastle.Math.EC.Multiplier;

namespace Org.BouncyCastle.Math.EC
{
    /**
     * base class for points on elliptic curves.
     */
    public abstract class ECPoint
    {
        private readonly ECCurve _curve;
        private readonly ECFieldElement _x, _y;
        private readonly bool _withCompression;

        protected internal ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression)
        {
            if (curve == null)
                throw new ArgumentNullException("curve");

            _curve = curve;
            _x = x;
            _y = y;
            _withCompression = withCompression;
        }

        public ECCurve Curve
        {
            get { return _curve; }
        }

        public ECFieldElement X
        {
            get { return _x; }
        }

        public ECFieldElement Y
        {
            get { return _y; }
        }

        public bool IsInfinity
        {
            get { return _x == null && _y == null; }
        }

        public bool IsCompressed
        {
            get { return _withCompression; }
        }

        public IECMultiplier Multiplier { get; set; }

        public IPreCompInfo PreCompInfo { get; set; }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            var o = obj as ECPoint;
            if (o == null)
                return false;

            if (this.IsInfinity)
                return o.IsInfinity;

            return _x.Equals(o._x) && _y.Equals(o._y);
        }

        public override int GetHashCode()
        {
            if (this.IsInfinity)
                return 0;

            return _x.GetHashCode() ^ _y.GetHashCode();
        }

        //		/**
        //		 * Mainly for testing. Explicitly set the <code>ECMultiplier</code>.
        //		 * @param multiplier The <code>ECMultiplier</code> to be used to multiply
        //		 * this <code>ECPoint</code>.
        //		 */
        //		internal void SetECMultiplier(
        //			ECMultiplier multiplier)
        //		{
        //			this.multiplier = multiplier;
        //		}

        public abstract byte[] GetEncoded();

        public abstract ECPoint Add(ECPoint b);
        public abstract ECPoint Subtract(ECPoint b);
        public abstract ECPoint Negate();
        public abstract ECPoint Twice();
        public abstract ECPoint Multiply(IBigInteger b);

        public abstract byte[] GetEncodedX();
        public abstract byte[] GetEncodedY();

        /**
        * Sets the appropriate <code>ECMultiplier</code>, unless already set. 
        */
        internal virtual void AssertECMultiplier()
        {
            if (Multiplier != null)
                return;

            lock (this)
            {
                if (Multiplier == null)
                {
                    Multiplier = new FpNafMultiplier();
                }
            }
        }
    }

    public abstract class ECPointBase : ECPoint
    {
        protected internal ECPointBase(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression)
            : base(curve, x, y, withCompression)
        {
        }

        protected internal abstract bool YTilde { get; }

        public override byte[] GetEncodedX()
        {
            return GetEncodedX(X9IntegerConverter.GetByteLength(this.X));
        }

        public byte[] GetEncodedX(int byteLength)
        {
            return X9IntegerConverter.IntegerToBytes(this.X.ToBigInteger(), byteLength);
        }

        public override byte[] GetEncodedY()
        {
            return GetEncodedY(X9IntegerConverter.GetByteLength(this.Y));
        }

        private byte[] GetEncodedY(int byteLength)
        {            
            return X9IntegerConverter.IntegerToBytes(this.Y.ToBigInteger(), byteLength);
        }

        /**
         * return the field element encoded with point compression. (S 4.3.6)
         */
        public override byte[] GetEncoded()
        {
            if (this.IsInfinity)
                return new byte[1];

            // Note: some of the tests rely on calculating byte length from the field element
            // (since the test cases use mismatching fields for curve/elements)
            var byteLength = X9IntegerConverter.GetByteLength(this.X);
            var x = this.GetEncodedX(byteLength);
            byte[] po;

            if (this.IsCompressed)
            {
                po = new byte[1 + x.Length];
                po[0] = (byte)(YTilde ? 0x03 : 0x02);
            }
            else
            {
                var y = this.GetEncodedY(byteLength);
                po = new byte[1 + x.Length + y.Length];

                po[0] = 0x04;

                y.CopyTo(po, 1 + x.Length);
            }

            x.CopyTo(po, 1);

            return po;
        }

        /**
         * Multiplies this <code>ECPoint</code> by the given number.
         * @param k The multiplicator.
         * @return <code>k * this</code>.
         */
        public override ECPoint Multiply(IBigInteger k)
        {
            if (k.SignValue < 0)
                throw new ArgumentException("The multiplicator cannot be negative", "k");

            if (this.IsInfinity)
                return this;

            if (k.SignValue == 0)
                return this.Curve.Infinity;

            AssertECMultiplier();
            return this.Multiplier.Multiply(this, k, this.PreCompInfo);
        }
    }

    /**
     * Elliptic curve points over Fp
     */
    public class FPPoint : ECPointBase
    {
        /**
         * Create a point which encodes with point compression.
         *
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         */
        public FPPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : this(curve, x, y, false)
        {
        }

        /**
         * Create a point that encodes with or without point compresion.
         *
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * @param withCompression if true encode with point compression
         */
        public FPPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression)
            : base(curve, x, y, withCompression)
        {
            if ((x != null && y == null) || (x == null && y != null))
                throw new ArgumentException("Exactly one of the field elements is null");
        }

        protected internal override bool YTilde
        {
            get
            {
                return this.Y.ToBigInteger().TestBit(0);
            }
        }

        // B.3 pg 62
        public override ECPoint Add(ECPoint b)
        {
            if (this.IsInfinity)
                return b;

            if (b.IsInfinity)
                return this;

            // Check if b = this or b = -this
            if (this.X.Equals(b.X))
            {
                if (this.Y.Equals(b.Y))
                {
                    // this = b, i.e. this must be doubled
                    return this.Twice();
                }

                Debug.Assert(this.Y.Equals(b.Y.Negate()));

                // this = -b, i.e. the result is the point at infinity
                return this.Curve.Infinity;
            }

            var gamma = b.Y.Subtract(this.Y).Divide(b.X.Subtract(this.X));

            var x3 = gamma.Square().Subtract(this.X).Subtract(b.X);
            var y3 = gamma.Multiply(this.X.Subtract(x3)).Subtract(this.Y);

            return new FPPoint(this.Curve, x3, y3);
        }

        // B.3 pg 62
        public override ECPoint Twice()
        {
            // Twice identity element (point at infinity) is identity
            if (this.IsInfinity)
                return this;

            // if y1 == 0, then (x1, y1) == (x1, -y1)
            // and hence this = -this and thus 2(x1, y1) == infinity
            if (this.Y.ToBigInteger().SignValue == 0)
                return this.Curve.Infinity;

            var two = this.Curve.FromBigInteger(BigInteger.Two);
            var three = this.Curve.FromBigInteger(BigInteger.Three);
            var gamma = this.X.Square().Multiply(three).Add(this.Curve.A).Divide(Y.Multiply(two));

            var x3 = gamma.Square().Subtract(this.X.Multiply(two));
            var y3 = gamma.Multiply(this.X.Subtract(x3)).Subtract(this.Y);

            return new FPPoint(this.Curve, x3, y3, this.IsCompressed);
        }

        // D.3.2 pg 102 (see Note:)
        public override ECPoint Subtract(ECPoint b)
        {
            return b.IsInfinity ? this : Add(b.Negate());
        }

        public override ECPoint Negate()
        {
            return new FPPoint(this.Curve, this.X, this.Y.Negate(), this.IsCompressed);
        }

        /**
         * Sets the default <code>ECMultiplier</code>, unless already set. 
         */
        internal override void AssertECMultiplier()
        {
            if (this.Multiplier == null)
            {
                lock (this)
                {
                    if (this.Multiplier == null)
                    {
                        this.Multiplier = new WNafMultiplier();
                    }
                }
            }
        }
    }

    /**
     * Elliptic curve points over F2m
     */
    public class F2MPoint : ECPointBase
    {
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         */
        public F2MPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : this(curve, x, y, false)
        {
        }

        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * @param withCompression true if encode with point compression.
         */
        public F2MPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression)
            : base(curve, x, y, withCompression)
        {
            if ((x != null && y == null) || (x == null && y != null))
            {
                throw new ArgumentException("Exactly one of the field elements is null");
            }

            if (x == null)
                return;

            // Check if x and y are elements of the same field
            F2MFieldElement.CheckFieldElements(this.X, this.Y);

            // Check if x and a are elements of the same field
            F2MFieldElement.CheckFieldElements(this.X, this.Curve.A);
        }

        /**
         * Constructor for point at infinity
         */
        [Obsolete("Use ECCurve.Infinity property")]
        public F2MPoint(
            ECCurve curve)
            : this(curve, null, null)
        {
        }

        protected internal override bool YTilde
        {
            get
            {
                // X9.62 4.2.2 and 4.3.6:
                // if x = 0 then ypTilde := 0, else ypTilde is the rightmost
                // bit of y * x^(-1)
                return this.X.ToBigInteger().SignValue != 0
                    && this.Y.Multiply(this.X.Invert()).ToBigInteger().TestBit(0);
            }
        }

        /**
         * Check, if two <code>ECPoint</code>s can be added or subtracted.
         * @param a The first <code>ECPoint</code> to check.
         * @param b The second <code>ECPoint</code> to check.
         * @throws IllegalArgumentException if <code>a</code> and <code>b</code>
         * cannot be added.
         */
        private static void CheckPoints(ECPoint a, ECPoint b)
        {
            // Check, if points are on the same curve
            if (!a.Curve.Equals(b.Curve))
                throw new ArgumentException("Only points on the same curve can be added or subtracted");

            //			F2mFieldElement.CheckFieldElements(a.x, b.x);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
         */
        public override ECPoint Add(ECPoint b)
        {
            CheckPoints(this, b);
            return AddSimple((F2MPoint)b);
        }

        /**
         * Adds another <code>ECPoints.F2m</code> to <code>this</code> without
         * checking if both points are on the same curve. Used by multiplication
         * algorithms, because there all points are a multiple of the same point
         * and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to add to
         * <code>this</code>.
         * @return <code>this + b</code>
         */
        internal F2MPoint AddSimple(F2MPoint b)
        {
            if (this.IsInfinity)
                return b;

            if (b.IsInfinity)
                return this;

            var x2 = (F2MFieldElement)b.X;
            var y2 = (F2MFieldElement)b.Y;

            // Check if b == this or b == -this
            if (this.X.Equals(x2))
            {
                // this == b, i.e. this must be doubled
                if (this.Y.Equals(y2))
                    return (F2MPoint)this.Twice();

                // this = -other, i.e. the result is the point at infinity
                return (F2MPoint)this.Curve.Infinity;
            }

            var xSum = this.X.Add(x2);
            var lambda = (F2MFieldElement)(this.Y.Add(y2)).Divide(xSum);
            var x3 = (F2MFieldElement)lambda.Square().Add(lambda).Add(xSum).Add(this.Curve.A);
            var y3 = (F2MFieldElement)lambda.Multiply(this.X.Add(x3)).Add(x3).Add(this.Y);

            return new F2MPoint(this.Curve, x3, y3, this.IsCompressed);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
         */
        public override ECPoint Subtract(
            ECPoint b)
        {
            CheckPoints(this, b);
            return SubtractSimple((F2MPoint)b);
        }

        /**
         * Subtracts another <code>ECPoints.F2m</code> from <code>this</code>
         * without checking if both points are on the same curve. Used by
         * multiplication algorithms, because there all points are a multiple
         * of the same point and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to subtract from
         * <code>this</code>.
         * @return <code>this - b</code>
         */
        internal F2MPoint SubtractSimple(
            F2MPoint b)
        {
            if (b.IsInfinity)
                return this;

            // Add -b
            return AddSimple((F2MPoint)b.Negate());
        }

        /* (non-Javadoc)
         * @see Org.BouncyCastle.Math.EC.ECPoint#twice()
         */
        public override ECPoint Twice()
        {
            // Twice identity element (point at infinity) is identity
            if (this.IsInfinity)
                return this;

            // if x1 == 0, then (x1, y1) == (x1, x1 + y1)
            // and hence this = -this and thus 2(x1, y1) == infinity
            if (this.X.ToBigInteger().SignValue == 0)
                return this.Curve.Infinity;

            var lambda = (F2MFieldElement)this.X.Add(this.Y.Divide(this.X));
            var x2 = (F2MFieldElement)lambda.Square().Add(lambda).Add(this.Curve.A);
            var one = this.Curve.FromBigInteger(BigInteger.One);
            var y2 = (F2MFieldElement)this.X.Square().Add(x2.Multiply(lambda.Add(one)));
            return new F2MPoint(this.Curve, x2, y2, this.IsCompressed);
        }

        public override ECPoint Negate()
        {
            return new F2MPoint(this.Curve, this.X, this.X.Add(this.Y), this.IsCompressed);
        }

        /**
         * Sets the appropriate <code>ECMultiplier</code>, unless already set. 
         */
        internal override void AssertECMultiplier()
        {
            if (this.Multiplier == null)
            {
                lock (this)
                {
                    if (this.Multiplier == null)
                    {
                        if (((F2MCurve)this.Curve).IsKoblitz)
                        {
                            this.Multiplier = new WTauNafMultiplier();
                        }
                        else
                        {
                            this.Multiplier = new WNafMultiplier();
                        }
                    }
                }
            }
        }
    }
}

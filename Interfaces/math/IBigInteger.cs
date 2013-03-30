namespace Org.BouncyCastle.Math
{
    public interface IBigInteger
    {           
        IBigInteger Abs();

        IBigInteger Add(
            IBigInteger value);

        IBigInteger And(
            IBigInteger value);

        IBigInteger AndNot(
            IBigInteger val);

        int BitCount { get; }
        int BitLength { get; }
        int IntValue { get; }
        long LongValue { get; }
        int SignValue { get; set; }
        int[] Magnitude { get; set; }

        int CompareTo(
            object obj);

        int CompareTo(
            IBigInteger value);

        IBigInteger Divide(
            IBigInteger val);

        IBigInteger[] DivideAndRemainder(
            IBigInteger val);

        bool Equals(
            object obj);

        IBigInteger Gcd(
            IBigInteger value);

        int GetHashCode();

        bool IsProbablePrime(
            int certainty);

        IBigInteger Max(
            IBigInteger value);

        IBigInteger Min(
            IBigInteger value);

        IBigInteger Mod(
            IBigInteger m);

        IBigInteger ModInverse(
            IBigInteger m);

        IBigInteger ModPow(
            IBigInteger exponent,
            IBigInteger m);

        IBigInteger Multiply(
            IBigInteger val);

        IBigInteger Negate();
        IBigInteger NextProbablePrime();
        IBigInteger Not();
        IBigInteger Pow(int exp);

        IBigInteger Remainder(
            IBigInteger n);

        IBigInteger ShiftLeft(
            int n);

        IBigInteger ShiftRight(
            int n);

        IBigInteger Subtract(
            IBigInteger n);

        byte[] ToByteArray();
        byte[] ToByteArrayUnsigned();
        string ToString();

        string ToString(
            int radix);

        int GetLowestSetBit();

        bool TestBit(
            int n);

        IBigInteger Or(
            IBigInteger value);

        IBigInteger Xor(
            IBigInteger value);

        IBigInteger SetBit(
            int n);

        IBigInteger ClearBit(
            int n);

        IBigInteger FlipBit(
            int n);

        bool QuickPow2Check();

        long GetMQuote();
    }
}
package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */

public class FpCurve
extends ECCurve
{
private final BigInteger q;
private final FpPoint infinity;

public FpCurve(BigInteger q, BigInteger a, BigInteger b)
{
  this.q = q;
  this.a = FromBigInteger(a);
  this.b = FromBigInteger(b);
  this.infinity = new FpPoint(this, null, null);
}

public BigInteger getQ()
{
  return this.q;
}

public int getFieldSize()
{
  return this.q.bitLength();
}

public final ECFieldElement FromBigInteger(BigInteger x)
{
  return new FpFieldElement(this.q, x);
}

public ECPoint CreatePoint(BigInteger x, BigInteger y, boolean withCompression)
{
  return new FpPoint(this, FromBigInteger(x), FromBigInteger(y), withCompression);
}

public ECPoint getInfinity()
{
  return this.infinity;
}

protected ECPoint DecompressPoint(int yTilde, BigInteger X1)
{
  ECFieldElement x = FromBigInteger(X1);
  ECFieldElement alpha = x.Square().Add(this.a).Multiply(x).Add(this.b);
  ECFieldElement beta = alpha.Sqrt();
  if (beta == null) {
    throw new ArithmeticException("Invalid point compression");
  }
  BigInteger betaValue = beta.ToBigInteger();
  int bit0 = betaValue.testBit(0) ? 1 : 0;
  if (bit0 != yTilde) {
    beta = FromBigInteger(this.q.subtract(betaValue));
  }
  return new FpPoint(this, x, beta, true);
}

public boolean equals(Object other)
{
  if (other == this) {
    return true;
  }
  if (!(other instanceof FpCurve)) {
    return false;
  }
  FpCurve o = (FpCurve)other;
  return (this.a.equals(o.a)) && (this.b.equals(o.b)) && (this.q.equals(o.q));
}

public int hashCode()
{
  return this.a.hashCode() ^ this.b.hashCode() ^ this.q.hashCode();
}
}

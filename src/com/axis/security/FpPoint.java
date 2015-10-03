package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */

public class FpPoint
  extends ECPoint
{
  public FpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
  {
    this(curve, x, y, false);
  }
  
  public FpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
  {
    super(curve, x, y, withCompression);
    if (((x != null) && (y == null)) || ((x == null) && (y != null))) {
      throw new IllegalArgumentException("Exactly one of the field elements is null");
    }
  }
  
  protected boolean getCompressionYTilde()
  {
    return getY().ToBigInteger().testBit(0);
  }
  
  public ECPoint Add(ECPoint b)
  {
    if (IsInfinity()) {
      return b;
    }
    if (b.IsInfinity()) {
      return this;
    }
    if (this.x.equals(b.x))
    {
      if (this.y.equals(b.y)) {
        return Twice();
      }
      return this.curve.getInfinity();
    }
    ECFieldElement gamma = b.y.Subtract(this.y).Divide(b.x.Subtract(this.x));
    
    ECFieldElement x3 = gamma.Square().Subtract(this.x).Subtract(b.x);
    ECFieldElement y3 = gamma.Multiply(this.x.Subtract(x3)).Subtract(this.y);
    
    return new FpPoint(this.curve, x3, y3);
  }
  
  public ECPoint Twice()
  {
    if (IsInfinity()) {
      return this;
    }
    if (this.y.ToBigInteger().signum() == 0) {
      return this.curve.getInfinity();
    }
    ECFieldElement TWO = this.curve.FromBigInteger(BigInteger.valueOf(2L));
    ECFieldElement THREE = this.curve.FromBigInteger(BigInteger.valueOf(3L));
    ECFieldElement gamma = this.x.Square().Multiply(THREE).Add(this.curve.getA()).Divide(this.y.Multiply(TWO));
    
    ECFieldElement x3 = gamma.Square().Subtract(this.x.Multiply(TWO));
    ECFieldElement y3 = gamma.Multiply(this.x.Subtract(x3)).Subtract(this.y);
    
    return new FpPoint(this.curve, x3, y3, this.withCompression);
  }
  
  public ECPoint Subtract(ECPoint b)
  {
    if (b.IsInfinity()) {
      return this;
    }
    return Add(b.Negate());
  }
  
  public ECPoint Negate()
  {
    return new FpPoint(this.curve, this.x, this.y.Negate(), this.withCompression);
  }
}

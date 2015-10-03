package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */

public abstract class ECFieldElement
{
  public abstract BigInteger ToBigInteger();
  
  public abstract String getFieldName();
  
  public abstract int getFieldSize();
  
  public abstract ECFieldElement Add(ECFieldElement paramECFieldElement);
  
  public abstract ECFieldElement Subtract(ECFieldElement paramECFieldElement);
  
  public abstract ECFieldElement Multiply(ECFieldElement paramECFieldElement);
  
  public abstract ECFieldElement Divide(ECFieldElement paramECFieldElement);
  
  public abstract ECFieldElement Negate();
  
  public abstract ECFieldElement Square();
  
  public abstract ECFieldElement Invert();
  
  public abstract ECFieldElement Sqrt();
  
  public abstract byte[] GetEncoded();
  
  public String toString()
  {
    return Utils.ToString(GetEncoded());
  }
}
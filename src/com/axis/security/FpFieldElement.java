package com.axis.security;

import java.math.BigInteger;
import java.util.Random;

/**
 * @author axis
 * @date 2015年9月30日
 */

public class FpFieldElement
  extends ECFieldElement
{
  private final BigInteger q;
  private final BigInteger x;
  
  public FpFieldElement(BigInteger q, BigInteger x)
  {
    if ((x == null) || (x.signum() < 0) || (x.compareTo(q) >= 0)) {
      throw new IllegalArgumentException("x value invalid in Fp field element");
    }
    this.q = q;
    this.x = x;
  }
  
  public BigInteger ToBigInteger()
  {
    return this.x;
  }
  
  public String getFieldName()
  {
    return "Fp";
  }
  
  public int getFieldSize()
  {
    return this.q.bitLength();
  }
  
  public BigInteger getQ()
  {
    return this.q;
  }
  
  public ECFieldElement Add(ECFieldElement b)
  {
    return new FpFieldElement(this.q, this.x.add(b.ToBigInteger()).mod(this.q));
  }
  
  public ECFieldElement Subtract(ECFieldElement b)
  {
    return new FpFieldElement(this.q, this.x.subtract(b.ToBigInteger()).mod(this.q));
  }
  
  public ECFieldElement Multiply(ECFieldElement b)
  {
    return new FpFieldElement(this.q, this.x.multiply(b.ToBigInteger()).mod(this.q));
  }
  
  public ECFieldElement Divide(ECFieldElement b)
  {
    return new FpFieldElement(this.q, this.x.multiply(b.ToBigInteger().modInverse(this.q)).mod(this.q));
  }
  
  public ECFieldElement Negate()
  {
    return new FpFieldElement(this.q, this.x.negate().mod(this.q));
  }
  
  public ECFieldElement Square()
  {
    return new FpFieldElement(this.q, this.x.multiply(this.x).mod(this.q));
  }
  
  public ECFieldElement Invert()
  {
    return new FpFieldElement(this.q, this.x.modInverse(this.q));
  }
  
  public ECFieldElement Sqrt()
  {
    if (!this.q.testBit(0)) {
      throw new UnsupportedOperationException("even value of q");
    }
    if (this.q.testBit(1))
    {
      ECFieldElement z = new FpFieldElement(this.q, this.x.modPow(this.q.shiftRight(2).add(BigInteger.ONE), this.q));
      return z.Square().equals(this) ? z : null;
    }
    BigInteger u = this.q.shiftRight(3);
    if (this.q.testBit(2))
    {
      BigInteger z = this.x.modPow(u.shiftLeft(1).add(BigInteger.ONE), this.q);
      if (z.equals(BigInteger.ONE)) {
        return new FpFieldElement(this.q, this.x.modPow(u.add(BigInteger.ONE), this.q));
      }
      if (z.equals(this.q.subtract(BigInteger.ONE))) {
        return new FpFieldElement(this.q, this.x.shiftLeft(1).multiply(this.x.shiftLeft(2).modPow(u, this.q)).mod(this.q));
      }
      return null;
    }
    BigInteger qMinusOne = this.q.subtract(BigInteger.ONE);
    
    BigInteger legendreExponent = qMinusOne.shiftRight(1);
    if (!this.x.modPow(legendreExponent, this.q).equals(BigInteger.ONE)) {
      return null;
    }
    BigInteger k = legendreExponent.add(BigInteger.ONE);
    BigInteger fourY = this.x.shiftLeft(2).mod(this.q);
    

    Random rand = new Random();
    BigInteger U;
    do
    {
      BigInteger r;
      do
      {
        r = new BigInteger(this.q.bitLength(), rand);
      } while ((r.compareTo(this.q) >= 0) || 
        (!r.multiply(r).subtract(fourY).modPow(legendreExponent, this.q).equals(qMinusOne)));
      BigInteger[] result = LucasSequence(this.q, r, this.x, k);
      U = result[0];
      BigInteger V = result[1];
      if (V.multiply(V).mod(this.q).equals(fourY))
      {
        if (V.testBit(0)) {
          V = V.add(this.q);
        }
        return new FpFieldElement(this.q, V.shiftRight(1).mod(this.q));
      }
    } while ((U.equals(BigInteger.ONE)) || (U.equals(qMinusOne)));
    return null;
  }
  
  private static BigInteger[] LucasSequence(BigInteger p, BigInteger X, BigInteger Y, BigInteger k)
  {
    int n = k.bitLength();
    int s = k.getLowestSetBit();
    
    BigInteger D = X.multiply(X).subtract(Y.shiftLeft(2));
    BigInteger U = BigInteger.ONE;
    BigInteger V = X;
    for (int j = n - 1; j >= s; j--) {
      if (k.testBit(j))
      {
        BigInteger T = X.multiply(U).add(V).shiftRight(1).mod(p);
        V = X.multiply(V).add(D.multiply(U)).shiftRight(1).mod(p);
        U = T;
      }
      else
      {
        BigInteger T = U.multiply(V).mod(p);
        V = V.multiply(V).add(D.multiply(U.multiply(U))).shiftRight(1).mod(p);
        U = T;
      }
    }
    for (int j = 1; j <= s; j++)
    {
      BigInteger T = U.multiply(V).mod(p);
      V = V.multiply(V).add(D.multiply(U.multiply(U))).shiftRight(1).mod(p);
      U = T;
    }
    return new BigInteger[] { U, V };
  }
  
  public byte[] GetEncoded()
  {
    int FieldSizeInBytes = this.q.bitLength() + 7 >> 3;
    byte[] bytes = Utils.asUnsignedByteArray(this.x);
    if (bytes.length > FieldSizeInBytes)
    {
      byte[] tmp = new byte[FieldSizeInBytes];
      System.arraycopy(bytes, bytes.length - FieldSizeInBytes, tmp, 0, FieldSizeInBytes);
      return tmp;
    }
    if (bytes.length < FieldSizeInBytes)
    {
      byte[] tmp = new byte[FieldSizeInBytes];
      System.arraycopy(bytes, 0, tmp, FieldSizeInBytes - bytes.length, bytes.length);
      return tmp;
    }
    return bytes;
  }
  
  public boolean equals(Object other)
  {
    if (other == this) {
      return true;
    }
    if (!(other instanceof FpFieldElement)) {
      return false;
    }
    FpFieldElement o = (FpFieldElement)other;
    return (this.q.equals(o.q)) && (this.x.equals(o.x));
  }
  
  public int hashCode()
  {
    return this.q.hashCode() ^ this.x.hashCode();
  }
}

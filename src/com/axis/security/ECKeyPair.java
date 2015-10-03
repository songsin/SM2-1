/**
 * 
 */
package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */
public class ECKeyPair
{
  public final BigInteger PrivateKey;
  public final ECPoint PublicKey;
  
  public ECKeyPair(BigInteger privateKey, ECPoint publicKey)
  {
    this.PrivateKey = privateKey;
    this.PublicKey = publicKey;
  }
}

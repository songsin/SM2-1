/**
 * 
 */
package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */
public class SM2KeyExchangeInformation
{
  public BigInteger PrivateKey;
  public ECPoint PublicKey;
  public BigInteger r;
  public ECPoint R;
  public byte[] Z;
  public byte[] PartnerZ;
  public ECPoint PartnerPublicKey;
  public ECPoint PartnerR;
  public byte[] S1;
  public byte[] S2;
  public byte[] PartnerS;
}

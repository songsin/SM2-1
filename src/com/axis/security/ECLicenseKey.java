/**
 * 
 */
package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */

public class ECLicenseKey
{
  public final BigInteger mKey;
  public final BigInteger mHash;
  
  public ECLicenseKey(BigInteger key, BigInteger hash)
  {
    this.mKey = key;
    this.mHash = hash;
  }
}

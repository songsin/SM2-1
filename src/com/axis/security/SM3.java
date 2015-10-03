package com.axis.security;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * @author axis
 * @date 2015年9月30日
 */

public class SM3
  implements Closeable
{
  public static final int HashSizeInBytes = 32;
  public static final int BlockSizeInBytes = 64;
  
  public String getAlgorithmName()
  {
    return "SM3";
  }
  
  public int getHashSize()
  {
    return 256;
  }
  
  private static final int[] IV = { 1937774191, 1226093241, 388252375, -628488704, -1452330820, 372324522, -477237683, -1325724082 };
  private static final byte[] SM3_PADDING = { Byte.MIN_VALUE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  private final int[] V = new int[8];
  private final int[] W = new int[68];
  private final byte[] M = new byte[4];
  private long BytesCount = 0L;
  private int WOff = 0;
  private int MOff = 0;
  
  public SM3()
  {
    Initialize();
  }
  
  public SM3(SM3 Source)
  {
    this.BytesCount = Source.BytesCount;
    
    this.WOff = Source.WOff;
    if (this.WOff > 0) {
      System.arraycopy(Source.W, 0, this.W, 0, this.WOff);
    }
    this.MOff = Source.MOff;
    if (this.MOff > 0) {
      System.arraycopy(Source.M, 0, this.M, 0, this.MOff);
    }
    System.arraycopy(Source.V, 0, this.V, 0, this.V.length);
  }
  
  protected final void Initialize()
  {
    this.BytesCount = 0L;
    this.WOff = 0;
    this.MOff = 0;
    
    System.arraycopy(IV, 0, this.V, 0, this.V.length);
    
    Arrays.fill(this.W, 0);
  }
  
  public void Update(byte input)
  {
    this.M[(this.MOff++)] = input;
    if (this.MOff == 4)
    {
      ProcessWord(this.M, 0);
      this.MOff = 0;
    }
    this.BytesCount += 1L;
  }
  
  public void BlockUpdate(byte[] input, int offset, int count)
  {
    while ((this.MOff != 0) && (count > 0))
    {
      Update(input[offset]);
      offset++;
      count--;
    }
    while (count >= 4)
    {
      ProcessWord(input, offset);
      
      offset += 4;
      count -= 4;
      this.BytesCount += 4L;
    }
    while (count > 0)
    {
      Update(input[offset]);
      offset++;
      count--;
    }
  }
  
  public void BlockUpdate(byte[] input)
  {
    BlockUpdate(input, 0, input.length);
  }
  
  public byte[] DoFinal()
    throws IOException
  {
    Finish();
    
    byte[] output = new byte[32];
    int i = 0;
    for (int n : this.V)
    {
      output[(i++)] = ((byte)(n >>> 24 & 0xFF));
      output[(i++)] = ((byte)(n >>> 16 & 0xFF));
      output[(i++)] = ((byte)(n >>> 8 & 0xFF));
      output[(i++)] = ((byte)(n & 0xFF));
    }
    Initialize();
    return output;
  }
  
  public int DoFinal(byte[] output, int offset)
    throws IOException
  {
    Finish();
    for (int n : this.V)
    {
      output[(offset++)] = ((byte)(n >>> 24 & 0xFF));
      output[(offset++)] = ((byte)(n >>> 16 & 0xFF));
      output[(offset++)] = ((byte)(n >>> 8 & 0xFF));
      output[(offset++)] = ((byte)(n & 0xFF));
    }
    Initialize();
    return 32;
  }
  
  public static byte[] ComputeHash(InputStream input)
    throws IOException
  {
    SM3 sm3 = new SM3();Throwable localThrowable3 = null;
    try
    {
      byte[] buffer = new byte['?'];
      int ReceivedBytes;
      do
      {
        ReceivedBytes = input.read(buffer);
        if (ReceivedBytes > 0) {
          sm3.BlockUpdate(buffer, 0, ReceivedBytes);
        }
      } while (ReceivedBytes > 0);
      return sm3.DoFinal();
    }
    catch (Throwable localThrowable1)
    {
      localThrowable3 = localThrowable1;throw localThrowable1;
    }
    finally
    {
      if (sm3 != null) {
        if (localThrowable3 != null) {
          try
          {
            sm3.close();
          }
          catch (Throwable localThrowable2)
          {
            localThrowable3.addSuppressed(localThrowable2);
          }
        } else {
          sm3.close();
        }
      }
    }
  }
  
  public static byte[] ComputeHash(byte[] input)
    throws IOException
  {
    SM3 sm3 = new SM3();Throwable localThrowable3 = null;
    try
    {
      sm3.BlockUpdate(input, 0, input.length);
      return sm3.DoFinal();
    }
    catch (Throwable localThrowable4)
    {
      localThrowable3 = localThrowable4;throw localThrowable4;
    }
    finally
    {
      if (sm3 != null) {
        if (localThrowable3 != null) {
          try
          {
            sm3.close();
          }
          catch (Throwable localThrowable2)
          {
            localThrowable3.addSuppressed(localThrowable2);
          }
        } else {
          sm3.close();
        }
      }
    }
  }
  
  public static byte[] ComputeHash(byte[] input, int offset, int count)
    throws IOException
  {
    SM3 sm3 = new SM3();Throwable localThrowable3 = null;
    try
    {
      sm3.BlockUpdate(input, offset, count);
      return sm3.DoFinal();
    }
    catch (Throwable localThrowable4)
    {
      localThrowable3 = localThrowable4;throw localThrowable4;
    }
    finally
    {
      if (sm3 != null) {
        if (localThrowable3 != null) {
          try
          {
            sm3.close();
          }
          catch (Throwable localThrowable2)
          {
            localThrowable3.addSuppressed(localThrowable2);
          }
        } else {
          sm3.close();
        }
      }
    }
  }
  
  private void ProcessWord(byte[] input, int offset)
  {
    this.W[(this.WOff++)] = (input[offset] << 24 | (input[(offset + 1)] & 0xFF) << 16 | (input[(offset + 2)] & 0xFF) << 8 | input[(offset + 3)] & 0xFF);
    if (this.WOff == 16) {
      ProcessBlock();
    }
  }
  
  private void ProcessBlock()
  {
    int[] W1 = new int[64];
    for (int j = 16; j < 68; j++) {
      this.W[j] = (P1(this.W[(j - 16)] ^ this.W[(j - 9)] ^ Integer.rotateLeft(this.W[(j - 3)], 15)) ^ Integer.rotateLeft(this.W[(j - 13)], 7) ^ this.W[(j - 6)]);
    }
    for (int j = 0; j < 64; j++) {
      W1[j] = (this.W[j] ^ this.W[(j + 4)]);
    }
    int A = this.V[0];
    int B = this.V[1];
    int C = this.V[2];
    int D = this.V[3];
    int E = this.V[4];
    int F = this.V[5];
    int G = this.V[6];
    int H = this.V[7];
    for (int j = 0; j < 16; j++)
    {
      int Q = Integer.rotateLeft(A, 12);
      int SS1 = Integer.rotateLeft(Q + E + Integer.rotateLeft(2043430169, j), 7);
      int SS2 = SS1 ^ Q;
      int TT1 = FF0(A, B, C) + D + SS2 + W1[j];
      int TT2 = GG0(E, F, G) + H + SS1 + this.W[j];
      D = C;
      C = Integer.rotateLeft(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = Integer.rotateLeft(F, 19);
      F = E;
      E = P0(TT2);
    }
    for (int j = 16; j < 64; j++)
    {
      int Q = Integer.rotateLeft(A, 12);
      int SS1 = Integer.rotateLeft(Q + E + Integer.rotateLeft(2055708042, j), 7);
      int SS2 = SS1 ^ Q;
      int TT1 = FF1(A, B, C) + D + SS2 + W1[j];
      int TT2 = GG1(E, F, G) + H + SS1 + this.W[j];
      D = C;
      C = Integer.rotateLeft(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = Integer.rotateLeft(F, 19);
      F = E;
      E = P0(TT2);
    }
    this.V[0] ^= A;
    this.V[1] ^= B;
    this.V[2] ^= C;
    this.V[3] ^= D;
    this.V[4] ^= E;
    this.V[5] ^= F;
    this.V[6] ^= G;
    this.V[7] ^= H;
    
    this.WOff = 0;
  }
  
  private void Finish()
    throws IOException
  {
    long BitsLength = this.BytesCount << 3;
    
    int LeftBytes = (this.WOff << 2) + this.MOff;
    int PaddingBytes = LeftBytes < 56 ? 56 - LeftBytes : 120 - LeftBytes;
    
    BlockUpdate(SM3_PADDING, 0, PaddingBytes);
    
    byte[] L = Utils.ToByteArray(BitsLength);
    
    BlockUpdate(L, 0, 8);
  }
  
  private int FF0(int x, int y, int z)
  {
    return x ^ y ^ z;
  }
  
  private int FF1(int x, int y, int z)
  {
    return x & y | x & z | y & z;
  }
  
  private int GG0(int x, int y, int z)
  {
    return x ^ y ^ z;
  }
  
  private int GG1(int x, int y, int z)
  {
    return x & y | (x ^ 0xFFFFFFFF) & z;
  }
  
  private int P0(int x)
  {
    return x ^ Integer.rotateLeft(x, 9) ^ Integer.rotateLeft(x, 17);
  }
  
  private int P1(int x)
  {
    return x ^ Integer.rotateLeft(x, 15) ^ Integer.rotateLeft(x, 23);
  }
  
  public void close()
    throws IOException
  {
    Arrays.fill(this.V, 0);
  }
}
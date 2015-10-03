package com.axis.security;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.SecureRandom;

/**
 * @author axis
 * @date 2015年9月30日
 */

public class Utils {
	public static byte[] ToByteArray(long n) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream(8);
		try {
			DataOutputStream out = new DataOutputStream(stream);
			try {
				out.writeLong(n);
				return stream.toByteArray();
			} catch (Throwable localThrowable) {
				throw localThrowable;
			} finally {
			}
		} catch (Throwable localThrowable) {
			throw localThrowable;
		} finally {
			if (stream != null)
                            stream.close();
		}
	}

	public static byte[] GenerateRandom(int keySizeInBytes) {
		byte[] Key = new byte[keySizeInBytes];
		new SecureRandom().nextBytes(Key);
		return Key;
	}

	public static String ToString(byte[] input, int offset, int count) {
		StringBuilder sb = new StringBuilder(count << 1);
		for (int i = 0; i < count; i++) {
			byte b = input[(offset++)];
			sb.append(Integer.toHexString((b & 0xF0) >>> 4).toUpperCase());
			sb.append(Integer.toHexString(b & 0xF).toUpperCase());
		}
		return sb.toString();
	}

	public static String ToString(byte[] input) {
		return ToString(input, 0, input.length);
	}

	public static String ToString(byte[] input, int offset) {
		return ToString(input, offset, input.length - offset);
	}

	public static void IntegerToByteArray(byte[] destination, int destinationIndex, int[] source, int sourceIndex,
			int count, ByteOrder order) {
		if (order.equals(ByteOrder.LITTLE_ENDIAN)) {
			for (int i = 0; i < count; i++) {
				int n = source[(sourceIndex++)];
				destination[(destinationIndex++)] = ((byte) (n & 0xFF));
				destination[(destinationIndex++)] = ((byte) (n >> 8 & 0xFF));
				destination[(destinationIndex++)] = ((byte) (n >> 16 & 0xFF));
				destination[(destinationIndex++)] = ((byte) (n >>> 24));
			}
		} else {
			for (int i = 0; i < count; i++) {
				int n = source[(sourceIndex++)];
				destination[(destinationIndex++)] = ((byte) (n >>> 24));
				destination[(destinationIndex++)] = ((byte) (n >> 16 & 0xFF));
				destination[(destinationIndex++)] = ((byte) (n >> 8 & 0xFF));
				destination[(destinationIndex++)] = ((byte) (n & 0xFF));
			}
		}
	}

	public static void IntegerToByteArray(byte[] destination, int destinationIndex, int source, ByteOrder order) {
		if (order.equals(ByteOrder.LITTLE_ENDIAN)) {
			destination[(destinationIndex++)] = ((byte) (source & 0xFF));
			destination[(destinationIndex++)] = ((byte) (source >> 8 & 0xFF));
			destination[(destinationIndex++)] = ((byte) (source >> 16 & 0xFF));
			destination[(destinationIndex++)] = ((byte) (source >>> 24));
		} else {
			destination[(destinationIndex++)] = ((byte) (source >>> 24));
			destination[(destinationIndex++)] = ((byte) (source >> 16 & 0xFF));
			destination[(destinationIndex++)] = ((byte) (source >> 8 & 0xFF));
			destination[(destinationIndex++)] = ((byte) (source & 0xFF));
		}
	}

	public static void IntegerFromByteArray(int[] destination, int destinationIndex, byte[] source, int sourceIndex,
			int count, ByteOrder order) {
		if (order.equals(ByteOrder.LITTLE_ENDIAN)) {
			for (int i = 0; i < count; i += 4) {
				destination[(destinationIndex++)] = (source[(sourceIndex++)] & 0xFF
						| (source[(sourceIndex++)] & 0xFF) << 8 | (source[(sourceIndex++)] & 0xFF) << 16
						| source[(sourceIndex++)] << 24);
			}
		} else {
			for (int i = 0; i < count; i += 4) {
				destination[(destinationIndex++)] = (source[(sourceIndex++)] << 24
						| (source[(sourceIndex++)] & 0xFF) << 16 | (source[(sourceIndex++)] & 0xFF) << 8
						| source[(sourceIndex++)] & 0xFF);
			}
		}
	}

	public static int IntegerFromByteArray(byte[] source, int sourceIndex, ByteOrder order) {
		if (order.equals(ByteOrder.LITTLE_ENDIAN)) {
			return source[(sourceIndex++)] & 0xFF | (source[(sourceIndex++)] & 0xFF) << 8
					| (source[(sourceIndex++)] & 0xFF) << 16 | source[(sourceIndex++)] << 24;
		}
		return source[(sourceIndex++)] << 24 | (source[(sourceIndex++)] & 0xFF) << 16
				| (source[(sourceIndex++)] & 0xFF) << 8 | source[(sourceIndex++)] & 0xFF;
	}

	public static void Reverse(int[] array) {
		Reverse(array, 0, array.length);
	}

	public static void Reverse(int[] array, int offset, int count) {
		int LeftIndex = offset;
		for (int RightIndex = offset + count - 1; LeftIndex < RightIndex; RightIndex--) {
			int value = array[LeftIndex];
			array[LeftIndex] = array[RightIndex];
			array[RightIndex] = value;
			LeftIndex++;
		}
	}

	public static byte[] toPrimitives(Byte[] source) {
		byte[] destination = new byte[source.length];

		int i = 0;
		for (Byte b : source) {
			destination[(i++)] = b.byteValue();
		}
		return destination;
	}

	public static byte[] asUnsignedByteArray(BigInteger value) {
		byte[] bytes = value.toByteArray();
		if (bytes[0] == 0) {
			byte[] tmp = new byte[bytes.length - 1];

			System.arraycopy(bytes, 1, tmp, 0, tmp.length);

			return tmp;
		}
		return bytes;
	}

	public static byte[] KDF(byte[] Z, int KLen) throws IOException {
		SM3 sm3Base = new SM3();
		Throwable localThrowable3 = null;
		try {
			sm3Base.BlockUpdate(Z, 0, Z.length);
			return KDF(sm3Base, KLen);
		} catch (Throwable localThrowable4) {
			localThrowable3 = localThrowable4;
			throw localThrowable4;
		} finally {
			if (sm3Base != null) {
				if (localThrowable3 != null) {
					try {
						sm3Base.close();
					} catch (Throwable localThrowable2) {
						localThrowable3.addSuppressed(localThrowable2);
					}
				} else {
					sm3Base.close();
				}
			}
		}
	}

	public static byte[] KDF(SM3 sm3Base, int KLen) throws IOException {
		byte[] K = new byte[KLen];
		int Count = (KLen + 32 - 1) / 32;
		int i = 1;
		for (int Index = 0; i <= Count; Index += 32) {
			SM3 sm3 = new SM3(sm3Base);
			try {
				sm3.Update((byte) (i >> 24 & 0xFF));
				sm3.Update((byte) (i >> 16 & 0xFF));
				sm3.Update((byte) (i >> 8 & 0xFF));
				sm3.Update((byte) (i & 0xFF));
				if (i < Count) {
					System.arraycopy(sm3.DoFinal(), 0, K, Index, 32);
				} else {
					System.arraycopy(sm3.DoFinal(), 0, K, Index, KLen - Index);
				}
			} catch (Throwable localThrowable) {
				throw localThrowable;
			} finally {
				if (sm3 != null) {
                                    sm3.close();
				}
			}
			i++;
		}
		return K;
	}

	public static boolean IsZeroForAll(byte[] source) {
		for (byte b : source) {
			if (b != 0) {
				return false;
			}
		}
		return true;
	}
}
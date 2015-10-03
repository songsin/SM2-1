package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */

public abstract class ECCurve {

	protected ECFieldElement a;
	protected ECFieldElement b;

	public abstract int getFieldSize();

	public abstract ECFieldElement FromBigInteger(BigInteger paramBigInteger);

	public abstract ECPoint CreatePoint(BigInteger paramBigInteger1, BigInteger paramBigInteger2, boolean paramBoolean);

	public abstract ECPoint getInfinity();

	protected abstract ECPoint DecompressPoint(int paramInt, BigInteger paramBigInteger);

	public ECFieldElement getA() {
		return a;
	}

	public ECFieldElement getB() {
		return b;
	}

	public ECPoint DecodePoint(byte[] encoded, int offset, IntegerWrapper handleLength) {
		int FieldSizeInBytes = getFieldSize() + 7 >> 3;

		byte PC = encoded[offset];
		switch (PC) {

		case 0:
			handleLength.value = 1;
			return getInfinity();
		case 1:
		case 2:
		case 3:
			handleLength.value = (FieldSizeInBytes + 1);
			if (offset + handleLength.value > encoded.length)
				return null;
			BigInteger X = new BigInteger(1,
					java.util.Arrays.copyOfRange(encoded, offset + 1, offset + 1 + FieldSizeInBytes));
			return DecompressPoint(PC & 0x1, X);
		case 4:
		case 5:
		case 6:
		case 7:
			handleLength.value = ((FieldSizeInBytes << 1) + 1);
			if (offset + handleLength.value > encoded.length) {
				return null;
			}
			BigInteger X1 = new BigInteger(1,
					java.util.Arrays.copyOfRange(encoded, offset + 1, offset + 1 + FieldSizeInBytes));
			BigInteger Y = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, offset + 1 + FieldSizeInBytes,
					offset + 1 + FieldSizeInBytes + FieldSizeInBytes));
			return new FpPoint(this, FromBigInteger(X1), FromBigInteger(Y), false);
		}
		handleLength.value = 0;
		return null;
	}
}

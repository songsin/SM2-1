package com.axis.security;

import java.math.BigInteger;

/**
 * @author axis
 * @date 2015年9月30日
 */

public abstract class ECPoint {
	final ECCurve curve;
	final ECFieldElement x;
	final ECFieldElement y;
	final boolean withCompression;

	protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression) {
		if (curve == null) {
			throw new IllegalArgumentException("curve is null");
		}
		this.curve = curve;
		this.x = x;
		this.y = y;
		this.withCompression = withCompression;
	}

	public ECCurve getCurve() {
		return curve;
	}

	public ECFieldElement getX() {
		return x;
	}

	public ECFieldElement getY() {
		return y;
	}

	public boolean IsInfinity() {
		return (x == null) && (y == null);
	}

	public boolean IsCompressed() {
		return withCompression;
	}

	public abstract ECPoint Add(ECPoint paramECPoint);

	public abstract ECPoint Subtract(ECPoint paramECPoint);

	public abstract ECPoint Negate();

	public abstract ECPoint Twice();

	protected abstract boolean getCompressionYTilde();

	public byte[] GetEncoded(ECPointCompressionFlag flag) {
		if (IsInfinity()) {
			return new byte[] { 0 };
		}
		byte[] X = x.GetEncoded();

		int YIndex = X.length + 1;
		byte[] R;
		if (flag.equals(ECPointCompressionFlag.Compression)) {
			R = new byte[YIndex];
			R[0] = ((byte) (y.ToBigInteger().testBit(0) ? 3 : 2));
		} else {
			byte[] Y = y.GetEncoded();
			R = new byte[YIndex + Y.length];
			if (flag.equals(ECPointCompressionFlag.None)) {
				R[0] = 4;
			} else {
				R[0] = ((byte) (y.ToBigInteger().testBit(0) ? 7 : 6));
			}
			System.arraycopy(Y, 0, R, YIndex, Y.length);
		}

		System.arraycopy(X, 0, R, 1, X.length);

		return R;
	}

	public ECPoint Multiply(BigInteger k) {
		if (k.signum() < 0) {
			throw new IllegalArgumentException("The multiplicator cannot be negative");
		}
		if (IsInfinity()) {
			return this;
		}
		if (k.signum() == 0) {
			return curve.getInfinity();
		}
		BigInteger e = k;
		BigInteger h = e.multiply(BigInteger.valueOf(3L));

		ECPoint neg = Negate();
		ECPoint R = this;

		for (int i = h.bitLength() - 2; i > 0; i--) {
			R = R.Twice();

			boolean hBit = h.testBit(i);
			boolean eBit = e.testBit(i);

			if (hBit != eBit) {
				R = R.Add(hBit ? this : neg);
			}
		}

		return R;
	}

	public boolean equals(Object other) {
		if (other == this) {
			return true;
		}
		if (!(other instanceof ECPoint)) {
			return false;
		}
		ECPoint o = (ECPoint) other;
		if (IsInfinity()) {
			return o.IsInfinity();
		}
		return (x.equals(x)) && (y.equals(y));
	}

	public int hashCode() {
		if (IsInfinity())
			return 0;
		return x.hashCode() ^ y.hashCode();
	}
}

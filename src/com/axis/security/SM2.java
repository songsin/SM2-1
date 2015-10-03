/**
 * 
 */
package com.axis.security;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author axis
 * @date 2015年9月30日
 */
public class SM2 implements Closeable {

	public final BigInteger mP;
	public final BigInteger mA;
	public final BigInteger mB;
	public final BigInteger mN;
	public final BigInteger mGx;
	public final BigInteger mGy;
	public final FpCurve mCurve;
	public final FpPoint mPointG;
	public final int mFieldSizeInBytes;

	public String getKeyExchangeAlgorithm() {
		return "SM2DiffieHellman";
	}

	public String getSignatureAlgorithm() {
		return "SM2Dsa";
	}

	public static final String[] EC256 = { "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
			"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
			"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
			"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" };

	public static final String[] NISTEC256 = { "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
			"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
			"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
			"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5" };
	public static final String[] NISTEC384 = {
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
			"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
			"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
			"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F" };
	public static final String[] NISTEC521 = {
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
			"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
			"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
			"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650" };

	public SM2(BigInteger p, BigInteger a, BigInteger b, BigInteger n, BigInteger gx, BigInteger gy) {
		mP = p;
		mA = a;
		mB = b;
		mN = n;
		mGx = gx;
		mGy = gy;

		mCurve = new FpCurve(mP, mA, mB);
		mPointG = new FpPoint(mCurve, new FpFieldElement(mP, mGx), new FpFieldElement(mP, mGy));

		mFieldSizeInBytes = (p.bitLength() + 7 >> 3);
	}

	public SM2(String p, String a, String b, String n, String gx, String gy) {
		this(new BigInteger(p, 16), new BigInteger(a, 16), new BigInteger(b, 16), new BigInteger(n, 16),
				new BigInteger(gx, 16), new BigInteger(gy, 16));
	}

	public SM2() {
		this(EC256[0], EC256[1], EC256[2], EC256[3], EC256[4], EC256[5]);
	}

	public static SM2 CreateInstance(int bitLength) {
		if (bitLength == 256) {
			return new SM2(NISTEC256[0], NISTEC256[1], NISTEC256[2], NISTEC256[3], NISTEC256[4], NISTEC256[5]);
		}
		if (bitLength == 384) {
			return new SM2(NISTEC384[0], NISTEC384[1], NISTEC384[2], NISTEC384[3], NISTEC384[4], NISTEC384[5]);
		}
		if (bitLength == 521) {
			return new SM2(NISTEC521[0], NISTEC521[1], NISTEC521[2], NISTEC521[3], NISTEC521[4], NISTEC521[5]);
		}

		throw new UnsupportedOperationException();
	}

	public byte[] EncryptValue(byte[] data, ECPoint publicKey) throws IOException {
		if (publicKey.IsInfinity())
			return null;

		while (true) {
			ECKeyPair keyPair = GetKeyPair();
			ECPoint C1 = keyPair.PublicKey;
			ECPoint P2 = publicKey.Multiply(keyPair.PrivateKey);

			SM3 sm3C2 = new SM3();
			try {
				sm3C2.BlockUpdate(GetEncoded(P2.getX()));
				SM3 sm3C3 = new SM3(sm3C2);
				try {
					byte[] EncodedP2Y = GetEncoded(P2.getY());
					sm3C2.BlockUpdate(EncodedP2Y);
					byte[] T = Utils.KDF(sm3C2, data.length);
					if (Utils.IsZeroForAll(T) == false) {
						sm3C3.BlockUpdate(data);
						sm3C3.BlockUpdate(EncodedP2Y);
						byte[] C3 = sm3C3.DoFinal();
						sm3C3.close();

						byte[] EncodedC1 = GetEncoded(C1, ECPointCompressionFlag.None);
						int Index = EncodedC1.length - 1;
						byte[] R = new byte[Index + data.length + 32];

						System.arraycopy(EncodedC1, 1, R, 0, Index);

						for (int i = 0; i < data.length; i++) {
							R[(Index++)] = ((byte) (data[i] ^ T[i]));
						}

						System.arraycopy(C3, 0, R, Index, 32);

						return R;
					}
				} catch (Throwable localThrowable) {
					throw localThrowable;
				} finally {
				}
			} catch (Throwable localThrowable) {
				throw localThrowable;
			} finally {
				if (sm3C2 != null)
					sm3C2.close();
			}
		}
	}

	public byte[] DecryptValue(byte[] data, BigInteger privateKey) throws IOException {
		int MOff = this.mFieldSizeInBytes << 1;

		int MLen = data.length - MOff - 32;
		if (MLen <= 0)
			return null;

		BigInteger X = new BigInteger(1, Arrays.copyOfRange(data, 0, this.mFieldSizeInBytes));
		BigInteger Y = new BigInteger(1, Arrays.copyOfRange(data, this.mFieldSizeInBytes, this.mFieldSizeInBytes << 1));
		ECPoint C1 = new FpPoint(this.mCurve, this.mCurve.FromBigInteger(X), this.mCurve.FromBigInteger(Y), false);

		if (!Exist(C1))
			return null;

		ECPoint P2 = C1.Multiply(privateKey);

		SM3 sm3C2 = new SM3();
		try {
			sm3C2.BlockUpdate(GetEncoded(P2.getX()));
			SM3 sm3C3 = new SM3(sm3C2);
			try {
				byte[] EncodedP2Y = GetEncoded(P2.getY());
				sm3C2.BlockUpdate(EncodedP2Y);
				byte[] T = Utils.KDF(sm3C2, MLen);

				if (Utils.IsZeroForAll(T))
					return null;

				byte[] M = new byte[MLen];
				for (int i = 0; i < MLen; i++)
					M[i] = ((byte) (data[(MOff++)] ^ T[i]));

				sm3C3.BlockUpdate(M);
				sm3C3.BlockUpdate(EncodedP2Y);
				byte[] C3 = sm3C3.DoFinal();
				for (int i = 0; i < 32; i++) {
					if (C3[i] != data[(MOff++)])
						return null;
				}
				return M;
			} catch (Throwable localThrowable) {
				throw localThrowable;
			}
		} catch (Throwable localThrowable) {
			throw localThrowable;
		} finally {
			if (sm3C2 != null)
					sm3C2.close();
		}
	}

	public String getHashAlgorithm() {
		return "SM3";
	}

	public byte[] SignData(byte[] data, int offset, int count, byte[] userId, BigInteger privateKey)
			throws IOException {
		return SignDataWithZ(data, offset, count, ComputeZ(userId, mPointG.Multiply(privateKey)), privateKey);
	}

	public byte[] SignData(byte[] data, byte[] userId, BigInteger privateKey) throws IOException {
		return SignDataWithZ(data, 0, data.length, ComputeZ(userId, mPointG.Multiply(privateKey)), privateKey);
	}

	public byte[] SignDataWithZ(byte[] data, int offset, int count, byte[] Z, BigInteger privateKey)
			throws IOException {
		if (Z.length != 32) {
			return null;
		}

		SM3 sm3 = new SM3();
		BigInteger e;
		try {
			sm3.BlockUpdate(Z);
			sm3.BlockUpdate(data, offset, count);
			e = new BigInteger(1, sm3.DoFinal());
		} catch (Throwable localThrowable) {
			throw localThrowable;

		} finally {
			if (sm3 != null)
					sm3.close();
		}
		BigInteger r;
		BigInteger s;
		do {
			BigInteger k;
			do {
				ECKeyPair keyPair = GetKeyPair();
				k = keyPair.PrivateKey;
				ECPoint P1 = keyPair.PublicKey;
				r = e.add(P1.getX().ToBigInteger()).mod(mN);
			} while ((r.equals(BigInteger.ZERO)) || (r.add(k).equals(mN)));

			s = privateKey.add(BigInteger.ONE).modInverse(mN).multiply(k.subtract(r.multiply(privateKey)).mod(mN))
					.mod(mN);
		} while (s.equals(BigInteger.ZERO));

		byte[] R = new byte[mFieldSizeInBytes << 1];
		System.arraycopy(GetEncoded(r), 0, R, 0, mFieldSizeInBytes);
		System.arraycopy(GetEncoded(s), 0, R, mFieldSizeInBytes, mFieldSizeInBytes);

		return R;
	}

	public byte[] SignDataWithZ(byte[] data, byte[] Z, BigInteger privateKey) throws IOException {
		return SignDataWithZ(data, 0, data.length, Z, privateKey);
	}

	public boolean VerifyData(byte[] data, int offset, int count, byte[] userId, ECPoint publicKey, byte[] signature)
			throws IOException {
		return VerifyDataWithZ(data, offset, count, ComputeZ(userId, publicKey), publicKey, signature);
	}

	public boolean VerifyData(byte[] data, byte[] userId, ECPoint publicKey, byte[] signature) throws IOException {
		return VerifyDataWithZ(data, 0, data.length, ComputeZ(userId, publicKey), publicKey, signature);
	}

	public boolean VerifyDataWithZ(byte[] data, int offset, int count, byte[] Z, ECPoint publicKey, byte[] signature)
			throws IOException {
		if (signature.length != mFieldSizeInBytes << 1) {
			return false;
		}

		if (Z.length != 32) {
			return false;
		}

		BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, mFieldSizeInBytes));
		if ((r.compareTo(BigInteger.ZERO) != 1) || (r.compareTo(mN) != -1)) {
			return false;
		}
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, mFieldSizeInBytes, mFieldSizeInBytes << 1));
		if ((s.compareTo(BigInteger.ZERO) != 1) || (s.compareTo(mN) != -1)) {
			return false;
		}

		SM3 sm3 = new SM3();
		BigInteger e;
		try {
			sm3.BlockUpdate(Z);
			sm3.BlockUpdate(data, offset, count);
			e = new BigInteger(1, sm3.DoFinal());
		} catch (Throwable localThrowable) {
			throw localThrowable;

		} finally {
			if (sm3 != null)
					sm3.close();
		}
		BigInteger t = r.add(s).mod(mN);
		if (t.equals(BigInteger.ZERO)) {
			return false;
		}
		ECPoint P1 = mPointG.Multiply(s).Add(publicKey.Multiply(t));
		BigInteger R = e.add(P1.getX().ToBigInteger()).mod(mN);
		return R.equals(r);
	}

	public boolean VerifyDataWithZ(byte[] data, byte[] Z, ECPoint publicKey, byte[] signature) throws IOException {
		return VerifyDataWithZ(data, 0, data.length, Z, publicKey, signature);
	}

	public boolean KeyAgreement(SM2KeyExchangeInformation Information, boolean IsInitiator, int sharedKeyBytes,
			ByteArrayWrapper SharedKey, boolean withConfirm) throws IOException {
		if ((!Exist(Information.PartnerPublicKey)) || (!Exist(Information.PartnerR))) {
			return false;
		}

		if ((Information.PartnerZ == null) || (Information.PartnerZ.length != 32)) {
			return false;
		}

		BigInteger W1 = BigInteger.ONE.shiftLeft((mN.bitLength() >> 1) - 1);
		BigInteger W2 = W1.subtract(BigInteger.ONE);
		BigInteger X = W1.add(Information.R.getX().ToBigInteger().and(W2));
		BigInteger T = Information.PrivateKey.add(Information.r.multiply(X)).mod(mN);
		BigInteger PartnerX = W1.add(Information.PartnerR.getX().ToBigInteger().and(W2));
		ECPoint V = Information.PartnerPublicKey.Add(Information.PartnerR.Multiply(PartnerX)).Multiply(T);
		if (V.IsInfinity()) {
			return false;
		}

		byte[] Z = new byte[(mFieldSizeInBytes << 1) + 64];
		System.arraycopy(GetEncoded(V.getX()), 0, Z, 0, mFieldSizeInBytes);
		System.arraycopy(GetEncoded(V.getY()), 0, Z, mFieldSizeInBytes, mFieldSizeInBytes);

		if (IsInitiator) {
			System.arraycopy(Z, 0, Z, mFieldSizeInBytes << 1, 32);
			System.arraycopy(Information.PartnerZ, 0, Z, (mFieldSizeInBytes << 1) + 32, 32);
		} else {
			System.arraycopy(Information.PartnerZ, 0, Z, mFieldSizeInBytes << 1, 32);
			System.arraycopy(Z, 0, Z, (mFieldSizeInBytes << 1) + 32, 32);
		}
		SharedKey.data = Utils.KDF(Z, sharedKeyBytes);

		if (withConfirm) {

			SM3 sm3 = new SM3();
			try {
				sm3.BlockUpdate(GetEncoded(V.getX()));
				if (IsInitiator) {
					sm3.BlockUpdate(Information.Z);
					sm3.BlockUpdate(Information.PartnerZ);
					sm3.BlockUpdate(GetEncoded(Information.R.getX()));
					sm3.BlockUpdate(GetEncoded(Information.R.getY()));
					sm3.BlockUpdate(GetEncoded(Information.PartnerR.getX()));
					sm3.BlockUpdate(GetEncoded(Information.PartnerR.getY()));
				} else {
					sm3.BlockUpdate(Information.PartnerZ);
					sm3.BlockUpdate(Information.Z);
					sm3.BlockUpdate(GetEncoded(Information.PartnerR.getX()));
					sm3.BlockUpdate(GetEncoded(Information.PartnerR.getY()));
					sm3.BlockUpdate(GetEncoded(Information.R.getX()));
					sm3.BlockUpdate(GetEncoded(Information.R.getY()));
				}

				byte[] HashVX = sm3.DoFinal();
				sm3.Update((byte) 2);
				sm3.BlockUpdate(GetEncoded(V.getY()));
				sm3.BlockUpdate(HashVX);
				Information.S1 = sm3.DoFinal();

				sm3.Update((byte) 3);
				sm3.BlockUpdate(GetEncoded(V.getY()));
				sm3.BlockUpdate(HashVX);
				Information.S2 = sm3.DoFinal();
			} catch (Throwable localThrowable) {
				throw localThrowable;
			} finally {
				if (sm3 != null)
						sm3.close();
			}
		}
		return true;
	}

	public boolean KeyConfirm(SM2KeyExchangeInformation Information, boolean IsInitiator) {
		if ((Information.PartnerS == null) || (Information.PartnerS.length != 32))
			return false;
		if (IsInitiator) {
			for (int i = 0; i < 32; i++) {
				if (Information.S1[i] != Information.PartnerS[i]) {
					return false;
				}

			}
		} else {
			for (int i = 0; i < 32; i++) {
				if (Information.S2[i] != Information.PartnerS[i]) {
					return false;
				}
			}
		}
		return true;
	}

	public byte[] ComputeZ(byte[] userId, ECPoint publicKey) throws IOException {
		SM3 sm3 = new SM3();
		try {
			int BitsLength = userId.length << 3;
			sm3.Update((byte) (BitsLength >> 8 & 0xFF));
			sm3.Update((byte) (BitsLength & 0xFF));

			sm3.BlockUpdate(userId);
			sm3.BlockUpdate(GetEncoded(mA));
			sm3.BlockUpdate(GetEncoded(mB));
			sm3.BlockUpdate(GetEncoded(mGx));
			sm3.BlockUpdate(GetEncoded(mGy));
			sm3.BlockUpdate(GetEncoded(publicKey.getX()));
			sm3.BlockUpdate(GetEncoded(publicKey.getY()));

			return sm3.DoFinal();
		} catch (Throwable localThrowable) {
			throw localThrowable;
		} finally {

			if (sm3 != null)
				sm3.close();
		}
	}

	public ECLicenseKey LicenseKeyMaker(byte[] userId, BigInteger PrivateKey) throws IOException {
		ECKeyPair keyPair = GetKeyPair();
		SM3 sm3 = new SM3();
		try {
			sm3.BlockUpdate(userId);
			sm3.BlockUpdate(GetEncoded(keyPair.PublicKey.getX()));
			sm3.BlockUpdate(GetEncoded(keyPair.PublicKey.getY()));
			BigInteger hash = new BigInteger(1, sm3.DoFinal());
			return new ECLicenseKey(PrivateKey.subtract(hash.multiply(PrivateKey)).mod(mN), hash);
		} catch (Throwable localThrowable) {
			throw localThrowable;
		} finally {

			if (sm3 != null) {
				sm3.close();
			}
		}
	}

	public ECLicenseKey LicenseKeyMaker(byte[] userId, BigInteger PrivateKey, BigInteger r) throws IOException {
		if ((r.compareTo(BigInteger.ZERO) <= 0) || (r.compareTo(mN.subtract(BigInteger.ONE)) >= 0)
				|| (PrivateKey.equals(r))) {
			return null;
		}

		ECPoint R = mPointG.Multiply(r);

		SM3 sm3 = new SM3();
		try {
			sm3.BlockUpdate(userId);
			sm3.BlockUpdate(GetEncoded(R.getX()));
			sm3.BlockUpdate(GetEncoded(R.getY()));
			BigInteger hash = new BigInteger(1, sm3.DoFinal());
			return new ECLicenseKey(r.subtract(hash.multiply(PrivateKey)).mod(mN), hash);
		} catch (Throwable localThrowable) {
			throw localThrowable;

		} finally {

			if (sm3 != null) {
				sm3.close();
			}
		}
	}

	public boolean LicenseKeyVerifier(byte[] userId, ECLicenseKey RegisterCode, ECPoint PublicKey) throws IOException {
		ECPoint R = mPointG.Multiply(RegisterCode.mKey).Add(PublicKey.Multiply(RegisterCode.mHash));
		SM3 sm3 = new SM3();
		try {
			sm3.BlockUpdate(userId);
			sm3.BlockUpdate(GetEncoded(R.x));
			sm3.BlockUpdate(GetEncoded(R.y));
			return RegisterCode.mHash.equals(new BigInteger(1, sm3.DoFinal()));
		} catch (Throwable localThrowable) {
			throw localThrowable;

		} finally {
			if (sm3 != null) {
				sm3.close();
			}
		}
	}

	private static final byte[] BitsMaskInByte = { -1, 127, 63, 31, 15, 7, 3, 1 };

	public ECKeyPair GetKeyPair() {
		int KeyFieldSize = mN.bitLength();
		int KeyLength = KeyFieldSize + 7 >> 3;
		int MaskBits = (KeyLength << 3) - KeyFieldSize;

		BigInteger d;
		do {
			byte[] b = Utils.GenerateRandom(KeyLength);
			int index = 0;
			byte[] tmp = b;
			tmp[index] = ((byte) (tmp[index] & BitsMaskInByte[MaskBits]));
			d = new BigInteger(1, b);
		} while ((d.compareTo(BigInteger.ZERO) <= 0) || (d.compareTo(mN.subtract(BigInteger.ONE)) >= 0));

		return new ECKeyPair(d, mPointG.Multiply(d));
	}

	public boolean Exist(ECPoint value) {
		if ((value == null) || (value.IsInfinity())) {
			return false;
		}
		ECFieldElement X = value.getX();
		ECFieldElement Y = value.getY();
		return Y.Square().equals(X.Square().Add(mCurve.FromBigInteger(mA)).Multiply(X).Add(mCurve.FromBigInteger(mB)));
	}

	public byte[] GetEncoded(ECPoint value, ECPointCompressionFlag flag) {
		if (value.IsInfinity()) {
			return new byte[] { 0 };
		}
		byte[] X = GetEncoded(value.getX());

		byte[] PO;
		if (flag.equals(ECPointCompressionFlag.Compression)) {
			PO = new byte[mFieldSizeInBytes + 1];
			PO[0] = ((byte) (value.getY().ToBigInteger().testBit(0) ? 3 : 2));
		} else {
			byte[] Y = GetEncoded(value.getY());
			PO = new byte[(mFieldSizeInBytes << 1) + 1];
			if (flag.equals(ECPointCompressionFlag.None)) {
				PO[0] = 4;
			} else {
				PO[0] = ((byte) (value.getY().ToBigInteger().testBit(0) ? 7 : 6));
			}
			System.arraycopy(Y, 0, PO, mFieldSizeInBytes + 1, mFieldSizeInBytes);
		}

		System.arraycopy(X, 0, PO, 1, mFieldSizeInBytes);
		return PO;
	}

	public byte[] GetEncoded(ECFieldElement value) {
		return GetEncoded(value.ToBigInteger());
	}

	public byte[] GetEncoded(BigInteger value) {
		byte[] bytes = Utils.asUnsignedByteArray(value);
		if (bytes.length > mFieldSizeInBytes) {
			byte[] tmp = new byte[mFieldSizeInBytes];
			System.arraycopy(bytes, bytes.length - mFieldSizeInBytes, tmp, 0, mFieldSizeInBytes);
			return tmp;
		}
		if (bytes.length < mFieldSizeInBytes) {
			byte[] tmp = new byte[mFieldSizeInBytes];
			System.arraycopy(bytes, 0, tmp, mFieldSizeInBytes - bytes.length, bytes.length);
			return tmp;
		}

		return bytes;
	}

	@Override
	public void close() throws IOException {

	}

}

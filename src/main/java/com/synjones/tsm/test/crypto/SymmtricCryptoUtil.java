/**
 * 
 */
package com.synjones.tsm.test.crypto;

import java.io.File;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;


/**
 * 锟皆称加斤拷锟杰癸拷锟斤拷锟斤拷
 * 
 * @author yiyuan.chen
 * @version $Id: SymmtricCryptoUtil.java, v 0.1 2011-2-16 锟斤拷锟斤拷07:46:03 yiyuan.chen
 *          Exp $
 */
public class SymmtricCryptoUtil {
	/**
	 * 锟皆称加斤拷锟斤拷(/CBC/PKCS5Padding模式) KMI默锟较碉拷锟斤拷/CBC/PKCS5Padding模式
	 * 
	 * @param text
	 *            锟斤拷锟�锟斤拷锟杰碉拷锟斤拷锟�
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷(锟斤拷锟斤拷)/锟斤拷锟侥ｏ拷锟斤拷锟杰ｏ拷锟斤拷
	 * @throws GeneralSecurityException
	 *             锟斤拷锟矫伙拷锟斤拷锟斤拷KMI锟斤拷锟斤拷锟杰的诧拷锟斤拷时,锟斤拷锟阶筹拷锟届常 锟斤拷锟斤拷钥锟斤拷莸某锟斤拷炔锟斤拷锟斤拷锟姐法要锟斤拷时,锟斤拷锟阶筹拷锟届常
	 */
	public static byte[] symmtricCrypto(byte[] text, byte[] keyData,
			String algorithm, int mode) throws GeneralSecurityException {
		String fullAlg = algorithm + "/CBC/PKCS5Padding";
		byte[] iv = initIv(fullAlg);
		return doCrypto(text, keyData, iv, fullAlg, "CBC", "PKCS5Padding", mode);
	}
	
	

	/**
	 * 锟皆称加斤拷锟斤拷(/CBC/?模式) KMI默锟较的癸拷锟斤拷模式锟斤拷CBC
	 * 
	 * @param text
	 *            锟斤拷锟�锟斤拷锟杰碉拷锟斤拷锟�
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param padding
	 *            锟斤拷锟侥Ｊ�目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷PKCS5Padding锟斤拷NoPadding.
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷(锟斤拷锟斤拷)/锟斤拷锟侥ｏ拷锟斤拷锟杰ｏ拷锟斤拷
	 * @throws GeneralSecurityException
	 *             锟斤拷锟矫伙拷锟斤拷锟斤拷KMI锟斤拷锟斤拷锟杰的诧拷锟斤拷时,锟斤拷锟阶筹拷锟届常 锟斤拷锟斤拷钥锟斤拷莸某锟斤拷炔锟斤拷锟斤拷锟姐法要锟斤拷时,锟斤拷锟阶筹拷锟届常
	 *             锟斤拷NoPadding锟斤拷锟侥Ｊ斤拷锟�锟斤拷锟斤拷锟斤拷艿锟斤拷锟捷诧拷锟斤拷锟斤拷应锟斤拷锟姐法锟侥匡拷锟叫★拷锟斤拷锟斤拷锟绞�锟斤拷锟阶筹拷锟届常
	 */
	public static byte[] symmtricCrypto(byte[] text, byte[] keyData,
			String algorithm, String padding, int mode)
			throws GeneralSecurityException {
		String fullAlg = algorithm + "/CBC/" + padding;
		byte[] iv = initIv(fullAlg);
		return doCrypto(text, keyData, iv, fullAlg, "CBC", padding, mode);
	}

	/**
	 * 锟皆称加斤拷锟斤拷(/?/?模式)
	 * 
	 * @param text
	 *            锟斤拷锟�锟斤拷锟杰碉拷锟斤拷锟�
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param workingMode
	 *            锟斤拷锟斤拷模式,目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷CBC锟斤拷ECB.
	 * @param padding
	 *            锟斤拷锟侥Ｊ�目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷PKCS5Padding锟斤拷NoPadding.
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷(锟斤拷锟斤拷)/锟斤拷锟侥ｏ拷锟斤拷锟杰ｏ拷锟斤拷
	 * @throws GeneralSecurityException
	 *             锟斤拷锟矫伙拷锟斤拷锟斤拷KMI锟斤拷锟斤拷锟杰的诧拷锟斤拷时,锟斤拷锟阶筹拷锟届常 锟斤拷锟斤拷钥锟斤拷莸某锟斤拷炔锟斤拷锟斤拷锟姐法要锟斤拷时,锟斤拷锟阶筹拷锟届常
	 *             锟斤拷NoPadding锟斤拷锟侥Ｊ斤拷锟�锟斤拷锟斤拷锟斤拷艿锟斤拷锟捷诧拷锟斤拷锟斤拷应锟斤拷锟姐法锟侥匡拷锟叫★拷锟斤拷锟斤拷锟绞�锟斤拷锟阶筹拷锟届常
	 */
	public static byte[] symmtricCrypto(byte[] text, byte[] keyData,
			String algorithm, String workingMode, String padding, int mode)
			throws GeneralSecurityException {
		String fullAlg = algorithm + "/" + workingMode + "/" + padding;
		byte[] iv = null;
		if (StringUtils.equals(workingMode, "CBC")) {
			iv = initIv(fullAlg);
		}
		return doCrypto(text, keyData, iv, fullAlg, workingMode, padding, mode);
	}

	/**
	 * 锟斤拷取锟皆称加斤拷锟斤拷锟斤拷锟斤拷锟斤拷姆锟斤拷锟斤拷锟斤拷锟�CBC/PKCS5Padding模式锟斤拷
	 * 
	 * @param file
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷锟斤拷
	 * @throws IOException
	 *             锟侥硷拷锟斤拷取锟斤拷锟斤拷锟绞憋拷锟斤拷壮锟斤拷锟届常锟斤拷
	 * @throws GeneralSecurityException
	 *             锟接斤拷锟斤拷失锟斤拷时锟阶筹拷锟斤拷斐ｏ拷锟�
	 */
	public static InputStream getInputStream(File file, byte[] keyData,
			String algorithm, int mode) throws IOException,
			GeneralSecurityException {
		return getInputStream(file, keyData, algorithm, "CBC", "PKCS5Padding",
				mode);
	}

	/**
	 * 锟斤拷取锟皆称加斤拷锟斤拷锟斤拷锟斤拷锟斤拷姆锟斤拷锟�
	 * 
	 * @param file
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param workingMode
	 *            锟斤拷锟斤拷模式,目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷CBC锟斤拷ECB.
	 * @param padding
	 *            锟斤拷锟侥Ｊ�目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷PKCS5Padding锟斤拷NoPadding.
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷锟斤拷
	 * @throws IOException
	 *             锟侥硷拷锟斤拷取锟斤拷锟斤拷锟绞憋拷锟斤拷壮锟斤拷锟届常锟斤拷
	 * @throws GeneralSecurityException
	 *             锟接斤拷锟斤拷失锟斤拷时锟阶筹拷锟斤拷斐ｏ拷锟�
	 */
	public static InputStream getInputStream(File file, byte[] keyData,
			String algorithm, String workingMode, String padding, int mode)
			throws IOException, GeneralSecurityException {
		String fullAlg = algorithm + "/CBC/PKCS5Padding";
		// 锟斤拷始锟斤拷锟斤拷锟斤拷锟斤拷
		FileInputStream fileInputStream = new FileInputStream(file);
		// 锟斤拷始锟斤拷cipher
		byte[] iv = initIv(fullAlg);
		Cipher cipher = getCipher(keyData, iv, fullAlg, workingMode, mode);
		return new CipherInputStream(fileInputStream, cipher);
	}

	/**
	 * 锟斤拷取锟皆称加斤拷锟斤拷锟斤拷锟斤拷锟侥凤拷锟斤拷锟斤拷锟斤拷/CBC/PKCS5Padding模式锟斤拷
	 * 
	 * @param file
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷锟�
	 * @throws IOException
	 *             锟侥硷拷锟斤拷取锟斤拷锟斤拷锟绞憋拷锟斤拷壮锟斤拷锟届常锟斤拷
	 * @throws GeneralSecurityException
	 *             锟接斤拷锟斤拷失锟斤拷时锟阶筹拷锟斤拷斐ｏ拷锟�
	 */
	public static OutputStream getOutputStream(File file, byte[] keyData,
			String algorithm, int mode) throws IOException,
			GeneralSecurityException {
		return getOutputStream(file, keyData, algorithm, "CBC", "PKCS5Padding",
				mode);
	}

	/**
	 * 锟斤拷取锟皆称加斤拷锟斤拷锟斤拷锟斤拷锟侥凤拷锟斤拷
	 * 
	 * @param file
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param algorithm
	 *            锟皆称硷拷锟斤拷锟姐法锟斤拷啤锟終MI默锟斤拷使锟斤拷3DES锟姐法锟斤拷锟斤拷锟斤拷DESede锟斤拷. 目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷: AES, Blowfish,
	 *            DESede
	 * @param workingMode
	 *            锟斤拷锟斤拷模式,目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷CBC锟斤拷ECB.
	 * @param padding
	 *            锟斤拷锟侥Ｊ�目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷PKCS5Padding锟斤拷NoPadding.
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷锟�
	 * @throws IOException
	 *             锟侥硷拷锟斤拷取锟斤拷锟斤拷锟绞憋拷锟斤拷壮锟斤拷锟届常锟斤拷
	 * @throws GeneralSecurityException
	 *             锟接斤拷锟斤拷失锟斤拷时锟阶筹拷锟斤拷斐ｏ拷锟�
	 */
	public static OutputStream getOutputStream(File file, byte[] keyData,
			String algorithm, String workingMode, String padding, int mode)
			throws IOException, GeneralSecurityException {
		String fullAlg = algorithm + "/CBC/PKCS5Padding";
		// 锟斤拷始锟斤拷锟斤拷锟斤拷锟�
		FileOutputStream fileOutputStream = new FileOutputStream(file);
		// 锟斤拷始锟斤拷cipher
		byte[] iv = initIv(fullAlg);
		Cipher cipher = getCipher(keyData, iv, fullAlg, workingMode, mode);
		return new CipherOutputStream(fileOutputStream, cipher);
	}

	/**
	 * 实锟街加斤拷锟杰的凤拷锟斤拷
	 * 
	 * @param text
	 *            锟斤拷锟�锟斤拷锟杰碉拷锟斤拷锟�
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param iv
	 *            锟斤拷始锟斤拷
	 * @param fullAlg
	 *            锟皆称硷拷锟斤拷锟姐法全锟斤拷eg.DESede/CBC/PKCS5Padding
	 * @param padding
	 *            锟斤拷锟侥Ｊ�目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷PKCS5Padding锟斤拷NoPadding.
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return 锟斤拷锟斤拷(锟斤拷锟斤拷)/锟斤拷锟侥ｏ拷锟斤拷锟杰ｏ拷锟斤拷
	 * @throws GeneralSecurityException
	 *             锟斤拷锟矫伙拷锟斤拷锟斤拷KMI锟斤拷锟斤拷锟杰的诧拷锟斤拷时,锟斤拷锟阶筹拷锟届常 锟斤拷锟斤拷钥锟斤拷莸某锟斤拷炔锟斤拷锟斤拷锟姐法要锟斤拷时,锟斤拷锟阶筹拷锟届常
	 *             锟斤拷NoPadding锟斤拷锟侥Ｊ斤拷锟�锟斤拷锟斤拷锟斤拷艿锟斤拷锟捷诧拷锟斤拷锟斤拷应锟斤拷锟姐法锟侥匡拷锟叫★拷锟斤拷锟斤拷锟绞�锟斤拷锟阶筹拷锟届常
	 */
	public static byte[] doCrypto(byte[] text, byte[] keyData, byte[] iv,
			String fullAlg, String workingMode, String padding, int mode)
			throws GeneralSecurityException {
		if (!StringUtils.equals(workingMode, "CBC")
				&& !StringUtils.equals(workingMode, "ECB")) {
			throw new GeneralSecurityException("锟斤拷锟斤拷墓锟斤拷锟侥Ｊ�目前KMI只支锟斤拷CBC锟斤拷ECB}锟街癸拷锟斤拷模式");
		}

		if (!StringUtils.equals(padding, "PKCS5Padding")
				&& !StringUtils.equals(padding, "NoPadding")) {
			throw new GeneralSecurityException(
					"锟斤拷锟斤拷锟斤拷锟斤拷模式,目前KMI只支锟斤拷PKCS5Padding锟斤拷NoPadding}锟街癸拷锟斤拷模式");
		}

		if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE) {
			throw new GeneralSecurityException(
					"锟斤拷锟斤拷募咏锟斤拷鼙锟绞�目前KMI只支锟斤拷Cipher.ENCRYPT_MODE锟斤拷Cipher.DECRYPT_MODE");
		}

		Cipher cipher = getCipher(keyData, iv, fullAlg, workingMode, mode);
		return cipher.doFinal(text);
	}
	

	/**
	 * 锟斤拷莶锟斤拷锟斤拷始锟斤拷cipher锟侥凤拷锟斤拷
	 * 
	 * @param keyData
	 *            锟斤拷钥锟斤拷锟�
	 * @param fullAlg
	 *            锟斤拷4锟斤拷始锟斤拷Cipher锟斤拷锟斤拷锟斤拷惴ㄈ拷锟�锟窖撅拷锟斤拷锟较癸拷锟斤拷模式锟斤拷锟斤拷锟侥Ｊ斤拷锟�
	 * @param workingMode
	 *            锟斤拷锟斤拷模式,目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷CBC锟斤拷ECB.
	 * @param padding
	 *            锟斤拷锟侥Ｊ�目前KMI锟斤拷锟杰的诧拷锟斤拷锟斤拷PKCS5Padding锟斤拷NoPadding.
	 * @param mode
	 *            锟接斤拷锟杰憋拷识锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.ENCRYPT_MODE锟斤拷锟斤拷锟杰★拷锟斤拷Cipher.DECRYPT_MODE锟斤拷
	 * @return cipher
	 * @throws GeneralSecurityException
	 */
	private static Cipher getCipher(byte[] keyData, byte[] iv, String fullAlg,
			String workingMode, int mode) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(fullAlg);
		SecretKey secretKey = new SecretKeySpec(keyData, StringUtils
				.substringBefore(fullAlg, "/"));

		if (StringUtils.equals(workingMode, "CBC")) {
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(mode, secretKey, ivSpec);
		} else {
			cipher.init(mode, secretKey);
		}
		return cipher;
	}
	
	/**
	 * 锟斤拷始锟斤拷锟侥凤拷锟斤拷
	 * 
	 * @param fullAlg
	 * @return
	 * @throws GeneralSecurityException
	 */
	private static byte[] initIv(String fullAlg)
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(fullAlg);
		int blockSize = cipher.getBlockSize();
		byte[] iv = new byte[blockSize];
		for (int i = 0; i < blockSize; ++i) {
			iv[i] = 0;
		}
		return iv;
	}
}

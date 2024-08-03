/**
 * Alipay.com Inc.
 * Copyright (c) 2004-2012 All Rights Reserved.
 */
package com.synjones.tsm.test.crypto;

import java.io.UnsupportedEncodingException;


import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



/**
 * 
 * ����ǩ������
 * 
 * @author geng.lin
 * @version $Id: SignUtilsImpl.java, v 0.1 2012-2-24 ����02:34:17 geng.lin Exp $
 */
public class SignUtilsImpl implements SignUtils {

	/**
	 * ��ǩ
	 * 
	 * @param text
	 *            ����
	 * @param key
	 *            ��Կ
	 * @param algorithm
	 *            ǩ���㷨,ĿǰKMI֧��NONEwithRSA, MD2withRSA, MD5withRSA, SHA1withRSA,
	 *            SHA256withRSA, SHA384withRSA, SHA512withRSA , SHA1withDSA
	 * @return ǩ��
	 * @throws Exception
	 */
	public String sign(final String text, final String key,
			final String algorithm) {
		final byte[] textBytes = text.getBytes();
		final byte[] keyBytes = Base64.decode(key);
		byte[] resultBytes = null;
		try {
			resultBytes = SignatureUtil.sign(textBytes, keyBytes, algorithm);
			return Base64.encode(resultBytes);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return "";
		}

	}

	/**
	 * ��ǩ
	 * 
	 * @param text
	 *            ����
	 * @param signText
	 *            ǩ��
	 * @param key
	 *            ��Կ
	 * @param algorithm
	 *            ��ǩ�㷨,ĿǰKMI֧��NONEwithRSA, MD2withRSA, MD5withRSA, SHA1withRSA,
	 *            SHA256withRSA, SHA384withRSA, SHA512withRSA , SHA1withDSA
	 * @return ��ǩͨ���true����ͨ���false
	 * @throws Exception
	 */
	public boolean verify(final String text, final String signText,
			final String key, final String algorithm) {

		try {
			return SignatureUtil.verify(text.getBytes(), Base64
					.decode(signText), Base64.decode(key), algorithm);
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * @see com.test.common.crypto.alipay.virtualprod.common.crypto.SignUtils#encrypt(String,
	 *      String, String)
	 */
	public String encrypt(String text, String key, String algorithm) {

		byte[] bytes = text.getBytes();
		byte[] keyData = Base64.decode(key); 

		try {
			byte[] cipherBytes = SymmtricCryptoUtil.symmtricCrypto(bytes,
					keyData, algorithm, Cipher.ENCRYPT_MODE);
			return Base64.encode(cipherBytes);
		} catch (GeneralSecurityException e) {
			return "";
		}
	}

	/**
	 * @see com.test.common.crypto.alipay.virtualprod.common.crypto.SignUtils#decrypt(String,
	 *      String, String)
	 */
	public String decrypt(String text, String key, String algorithm) {

		byte[] bytes = Base64.decode(text); 
		byte[] keyData = Base64.decode(key); 

		try {
			byte[] cipherBytes = SymmtricCryptoUtil.symmtricCrypto(bytes,
					keyData, algorithm, Cipher.DECRYPT_MODE);
		//	return new String(cipherBytes);
			return new String(cipherBytes,"UTF-8");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return "";
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}
		
	}

	
	

}

/**
 *
 */
package com.synjones.tsm.test.crypto;
import org.apache.commons.lang3.StringUtils;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
/**
 * 签锟斤拷锟斤拷锟�
 *
 * @author yiyuan.chen
 * @version $Id: SignatureUtil.java, v 0.1 2011-2-25 锟斤拷锟斤拷10:47:54 yiyuan.chen Exp
 *          $
 */
public class SignatureUtil {
  /**
   * 使锟斤拷私钥锟斤拷锟斤拷签锟斤拷姆锟斤拷锟�
   *
   * @param text
   *            锟斤拷签锟斤拷锟斤拷锟斤拷
   * @param privateKeyData
   *            私钥锟斤拷锟�
   * @param algorithm
   *            签锟斤拷锟姐法,目前KMI支锟斤拷NONEwithRSA, MD2withRSA, MD5withRSA, SHA1withRSA,
   *            SHA256withRSA, SHA384withRSA, SHA512withRSA , SHA1withDSA
   * @return 签锟斤拷锟斤拷锟斤拷锟�
   * @throws GeneralSecurityException
   */
  public static byte[] sign(byte[] text, byte[] privateKeyData, String algorithm) throws GeneralSecurityException {
    PrivateKey privateKey = getPrivateKey(privateKeyData, algorithm);
    Signature signatureChecker = Signature.getInstance(algorithm);
    signatureChecker.initSign(privateKey);
    signatureChecker.update(text);
    return signatureChecker.sign();
  }
  /**
   * 使锟矫癸拷钥锟斤拷锟斤拷锟斤拷签锟侥凤拷锟斤拷
   *
   * @param text
   *            原始锟斤拷锟斤拷锟斤拷
   * @param signedText
   *            签锟斤拷锟斤拷锟斤拷锟�
   * @param publicKeyData
   *            锟斤拷钥锟斤拷锟�
   * @param algorithm
   *            签锟斤拷锟姐法,目前KMI支锟斤拷NONEwithRSA, MD2withRSA, MD5withRSA, SHA1withRSA,
   *            SHA256withRSA, SHA384withRSA, SHA512withRSA , SHA1withDSA
   * @return 锟斤拷锟斤拷锟角╋拷晒锟�锟斤拷锟斤拷true,锟斤拷签失锟斤拷,锟斤拷锟斤拷false
   * @throws GeneralSecurityException
   */
  public static boolean verify(byte[] text, byte[] signedText, byte[] publicKeyData, String algorithm) throws GeneralSecurityException {
    PublicKey publicKey = getPublicKey(publicKeyData, algorithm);
    Signature signatureChecker = Signature.getInstance(algorithm);
    signatureChecker.initVerify(publicKey);
    signatureChecker.update(text);
    return signatureChecker.verify(signedText);
  }
  /**
   * 锟矫碉拷锟斤拷钥
   *
   * @param keyData
   *            锟斤拷钥锟斤拷锟�
   * @throws GeneralSecurityException
   */
  public static PublicKey getPublicKey(byte[] keyData, String algorithm) throws GeneralSecurityException {
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyData);
    KeyFactory keyFactory = KeyFactory.getInstance(StringUtils.substringAfter(algorithm, "with"));
    PublicKey publicKey = keyFactory.generatePublic(keySpec);
    return publicKey;
  }
  /**
   * 锟矫碉拷私钥
   *
   * @param keyData
   *            锟斤拷钥锟斤拷锟�
   * @throws GeneralSecurityException
   */
  public static PrivateKey getPrivateKey(byte[] keyData, String algorithm) throws GeneralSecurityException {
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
    KeyFactory keyFactory = KeyFactory.getInstance(StringUtils.substringAfter(algorithm, "with"));
    //System.out.println("keySpec==="+keySpec);
    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
    return privateKey;
  }
}
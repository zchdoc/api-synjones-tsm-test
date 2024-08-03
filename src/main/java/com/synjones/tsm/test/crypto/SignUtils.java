/**
 * Alipay.com Inc.
 * Copyright (c) 2004-2012 All Rights Reserved.
 */
package com.synjones.tsm.test.crypto;

/**
 * 
 * @author geng.lin
 * @version $Id: SignUtils.java, v 0.1 2012-3-6 ����11:00:32 geng.lin Exp $
 */
public interface SignUtils {

    /**
     * ��ǩ
     * 
     * @param text ����
     * @param key ��Կ
     * @param algorithm ǩ���㷨,ĿǰKMI֧��NONEwithRSA, MD2withRSA, MD5withRSA, SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA , SHA1withDSA
     * @return ǩ��
     * @throws Exception
     */
    public String sign(final String text, final String key, final String algorithm);

    /**
     * ��ǩ
     * 
     * @param text ����
     * @param signText ǩ��
     * @param key ��Կ
     * @param algorithm ��ǩ�㷨,ĿǰKMI֧��NONEwithRSA, MD2withRSA, MD5withRSA, SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA , SHA1withDSA
     * @return ��ǩͨ���true����ͨ���false
     * @throws Exception
     */
    public boolean verify(final String text, final String signText, final String key, final String algorithm);

    /**
     * ����
     * 
     * @param text ����
     * @param key ��Կ
     * @param algorithm �㷨
     * @return ����
     */
    public String encrypt(final String text, final String key, final String algorithm);

    /**
     * ����
     * 
     * @param text ����
     * @param key ��Կ
     * @param algorithm �㷨 
     * @return ����
     */
    public String decrypt(final String text, final String key, final String algorithm);
    
   
}

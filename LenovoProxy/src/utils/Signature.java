package utils;


import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;



import java.security.cert.X509Certificate;

public class Signature {
	
	//private final static String PLAN_TEXT = "E2EE key pair verify plan text";
	
	public static void main(String[] args) throws Exception
	{
		Signature sig = new Signature();
		//byte[] signedText = sign(null,"xxxx123");
		//System.out.println("verify:" + sig.verify(null,"xxxx123",signedText));
		/*String priKey = "E:\\tmp\\cert\\certificate\\e2ee_private_key.key";
		String pubKey = "E:\\tmp\\cert\\certificate\\e2ee_public_key.key";
		String cert = "E:\\tmp\\cert\\certificate\\e2ee_certificate.crt";*/
		String priKey = "/Users/i063103/tmp/cert/e2ee_private_key.key";
		String pubKey = "/Users/i063103/tmp/cert/e2ee_public_key.key";
		String cert = "/Users/i063103/tmp/cert/e2ee_certificate.crt";
		String password = "sybase1";
		sig.verifyE2eeKeyAndCertificatePair(priKey,pubKey,cert,password);
		System.out.println("it is ok");
	}
	
	private final static String PLAN_TEXT = "E2EE key pair verify plan text";
	
	private void verifyE2eeKeyAndCertificatePair(String e2eePrivateKey,String e2eePublicKey,String e2eeCertificate,String password) throws Exception
	{
		String privateKeyText = readKeyFile(e2eePrivateKey);
		String publickKeyText = readKeyFile(e2eePublicKey);
		PublicKey pubKey = getPubKeyFromCertificate(e2eeCertificate);
		
		String signText = signature(privateKeyText,PLAN_TEXT,password);
		
		if (!verifyWithPublicKey(publickKeyText,PLAN_TEXT,signText))
		{
			throw new Exception("E2EE public key does not match private key!");
		}
		
		if (!verifyWithCertificate(pubKey,PLAN_TEXT,signText))
		{
			throw new Exception("E2EE certificate does not match private key!");
		}
		
	}
	
	
	
	private String signature(String privateKeyText, String plainText, String password) throws Exception 
	{
		try {
			byte[] keyBytes = BinaryUtil.fromStringBase64(privateKeyText);
			EncryptedPrivateKeyInfo encryptPKInfo = new EncryptedPrivateKeyInfo(keyBytes);
			Cipher cipher = Cipher.getInstance(encryptPKInfo.getAlgName());
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secFac = SecretKeyFactory.getInstance(encryptPKInfo.getAlgName());
			Key pbeKey = secFac.generateSecret(pbeKeySpec);
			AlgorithmParameters algParams = encryptPKInfo.getAlgParameters();
			cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
			KeySpec pkcs8KeySpec = encryptPKInfo.getKeySpec(cipher);
			KeyFactory keyf = KeyFactory.getInstance("RSA");
			PrivateKey prikey = keyf.generatePrivate(pkcs8KeySpec);
			java.security.Signature signet = java.security.Signature
					.getInstance("MD5withRSA");
			signet.initSign(prikey);
			signet.update(plainText.getBytes());
			return BinaryUtil.toStringBase64(signet.sign());
		} catch (java.lang.Exception e) {
			
			throw e;
		}
		
	}
	
	public static boolean verifyWithPublicKey(String pubKeyText, String plainText, String signText) throws Exception 
	{
		try {
			java.security.spec.X509EncodedKeySpec bobPubKeySpec = new java.security.spec.X509EncodedKeySpec(
					BinaryUtil.fromStringBase64(pubKeyText));
			java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
			java.security.PublicKey pubKey = keyFactory.generatePublic(bobPubKeySpec);
			byte[] signed = BinaryUtil.fromStringBase64(signText);
			java.security.Signature signatureChecker = java.security.Signature.getInstance("MD5withRSA");
			signatureChecker.initVerify(pubKey);
			signatureChecker.update(plainText.getBytes());
			if (signatureChecker.verify(signed))
			{
				return true;
			}
			else
			{
				return false;
			}
		} catch (Exception e) {
		
			throw e;
		}
	}
	
	public static boolean verifyWithCertificate(PublicKey pubKey, String plainText, String signText) throws Exception {
		try {
			byte[] signed = BinaryUtil.fromStringBase64(signText);
			java.security.Signature signatureChecker = java.security.Signature.getInstance("MD5withRSA");
			signatureChecker.initVerify(pubKey);
			signatureChecker.update(plainText.getBytes());
			if (signatureChecker.verify(signed))
			{
				return true;
			}
			else
			{
				return false;
			}
		} catch (Exception e) {
			throw e;
		}
	}
	
	private PublicKey getPubKeyFromCertificate(String path) throws Exception
	{
		FileInputStream fin = new FileInputStream(path);
		
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		
		PublicKey pk = certificate.getPublicKey();
		return pk;
	}
	
	@SuppressWarnings("deprecation")
	private String readKeyFile(String path) throws IOException{
		File privateKeyFile = new File(path);
		FileInputStream fis = new FileInputStream(privateKeyFile);
		DataInputStream dis = new DataInputStream(fis);
		String txtLine = "";
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while (txtLine != null)
		{
			
			txtLine  = dis.readLine();
			if (txtLine == null) break;
			if (txtLine.startsWith("-----")) continue;
			baos.write(txtLine.getBytes());
		}
		baos.flush();
		dis.close();
		return baos.toString(); 
	}
	
	
	/**
	 * 
	 * Description:数字签名
	 * 
	 * @param priKeyText
	 * @param plainText
	 */
	public static byte[] sign(String privateKeyText, String plainText) {
		try {
			
			//String privateKeyText = readKeyFile("U:\\target\\Repository\\Certificate\\new\\e2ee_private_key.key");
			//String privateKeyText = readKeyFile("E:\\tmp\\tmp\\certificate\\e2ee_private_key.key");
			
			//System.out.println(Base64Binary.decode(privateKeyText));
			
			byte[] keyBytes = BinaryUtil.fromStringBase64(privateKeyText);
			
			String password = "sybase1";
			EncryptedPrivateKeyInfo encryptPKInfo = new EncryptedPrivateKeyInfo(keyBytes);
			Cipher cipher = Cipher.getInstance(encryptPKInfo.getAlgName());
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secFac = SecretKeyFactory.getInstance(encryptPKInfo.getAlgName());
			Key pbeKey = secFac.generateSecret(pbeKeySpec);
			AlgorithmParameters algParams = encryptPKInfo.getAlgParameters();
			cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
			KeySpec pkcs8KeySpec = encryptPKInfo.getKeySpec(cipher);
			
			//PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(
				//	Base64Binary.decode(privateKeyText));
			
			
			
			
			KeyFactory keyf = KeyFactory.getInstance("RSA");
			PrivateKey prikey = keyf.generatePrivate(pkcs8KeySpec);
			
			// 用私钥对信息生成数字签名
			java.security.Signature signet = java.security.Signature
					.getInstance("MD5withRSA");
			signet.initSign(prikey);
			signet.update(plainText.getBytes());
			byte[] signed = BinaryUtil.toStringBase64(signet.sign()).getBytes();
			return signed;
		} catch (java.lang.Exception e) {
			
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 
	 * Description:校验数字签名,此方法不会抛出任务异常,成功返回true,失败返回false,要求全部参数不能为空
	 * 
	 * @param pubKeyText
	 *            公钥,base64编码
	 * @param plainText
	 *            明文
	 * @since：2007-12-27 上午09:33:55
	 */
	public  boolean verify(byte[] pubKeyText, String plainText, byte[] signText) {
		try {
			
			//String pubKeyText1 = readKeyFile("U:\\target\\Repository\\Certificate\\new\\e2ee_public_key.key");
			String pubKeyText1 = readKeyFile("E:\\tmp\\tmp\\certificate\\e2ee_public_key.key");
			
			// 解密由base64编码的公钥,并构造X509EncodedKeySpec对象
			java.security.spec.X509EncodedKeySpec bobPubKeySpec = new java.security.spec.X509EncodedKeySpec(
					BinaryUtil.fromStringBase64(pubKeyText1));
			// RSA对称加密算法
			java.security.KeyFactory keyFactory = java.security.KeyFactory
					.getInstance("RSA");
			// 取公钥匙对象
			java.security.PublicKey pubKey = keyFactory
					.generatePublic(bobPubKeySpec);
			
			//pubKey = getPubKeyFromCertificate("U:\\target\\Repository\\Certificate\\new\\e2ee_certificate.crt");
			pubKey = getPubKeyFromCertificate("E:\\tmp\\tmp\\certificate\\e2ee_certificate.crt");
			// 解密由base64编码的数字签名
			byte[] signed = BinaryUtil.fromStringBase64(new String(signText));
			java.security.Signature signatureChecker = java.security.Signature
					.getInstance("MD5withRSA");
			signatureChecker.initVerify(pubKey);
			signatureChecker.update(plainText.getBytes());
			// 验证签名是否正常
			if (signatureChecker.verify(signed))
				return true;
			else
				return false;
		} catch (Throwable e) {
			System.out.println("校验签名失败");
			e.printStackTrace();
			return false;
		}
	}
	
	

}

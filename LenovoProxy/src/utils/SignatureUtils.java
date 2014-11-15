package utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.text.MessageFormat;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class SignatureUtils {
	
	public static void main(String[]  args) throws Exception
	{
		//showAlgorithm();
		//signature();
		buildPayload();
	}
	
	
	public static void showAlgorithm()
	{
		for (Provider provider : Security.getProviders()) {  
		    System.out.println("Provider: " + provider.getName());      
		    for (Provider.Service service : provider.getServices()){      
		    System.out.println("  Algorithm: " + service.getAlgorithm());     
		    }    
		    System.out.println("\n");  
		}   
		  
	}
	
	public static void signature() throws Exception
	{
		String before = "asdf";    
		 byte[] plainText = before.getBytes("UTF8");    
		  
		 //形成RSA公钥对    
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");    
		 keyGen.initialize(1024);    
		 KeyPair key = keyGen.generateKeyPair();    
		  
		 //使用私钥签名**********************************************************    
		 Signature sig = Signature.getInstance("SHA256withRSA");    
		 sig.initSign(key.getPrivate());//sig对象得到私钥    
		  
		  
		 //签名对象得到原始数据    
		 sig.update(plainText);//sig对象得到原始数据(现实中用的是原始数据的摘要，摘要的是单向的，即摘要算法后无法解密)    
		 byte[] signature = sig.sign();//sig对象用私钥对原始数据进行签名，签名后得到签名signature    
		 System.out.println(sig.getProvider().getInfo());    
		  
		  
		 String after1 = new String(signature, "UTF8");    
		 System.out.println("/n用私钥签名后:"+after1);    
		  
		 //使用公钥验证  
		 //key = keyGen.generateKeyPair();   
		 PublicKey pubKey = key.getPublic();
		 System.out.println("====="+pubKey.toString()+"###");
		 sig.initVerify(key.getPublic());//sig对象得到公钥   
		  
		  
		 //签名对象得到原始信息   
		 sig.update(plainText);//sig对象得到原始数据(现实中是摘要)    
		 try {    
		     if (sig.verify(signature)) {//sig对象用公钥解密签名signature得到原始数据(即摘要)，一致则true    
		         System.out.println("签名验证正确！！"+new String(plainText, "UTF8"));    
		     } else {    
		         System.out.println("签名验证失败！！");    
		     }    
		 } catch (SignatureException e) {    
		     System.out.println("签名验证失败！！");    
		 }    
	}

	
	public static void buildPayload()
	{
		String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

		String claimTemplate = "'{'\"iss\": \"{0}\", \"scope\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\", \"iat\": \"{4}\"'}'";

		try {
		StringBuffer token = new StringBuffer();

		//Encode the JWT Header and add it to our string to sign
		//token.append(Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));

		//Separate with a period
		token.append(".");

		//Create the JWT Claims Object
		String[] claimArray = new String[5];
		claimArray[0] = "lenovoreach.com@realm.passport.lenovo.com";
		claimArray[1] = "passport.lenovo.com/proxyapi";
		claimArray[2] = "https://passport.lenovo.com/interserver/accounts/1.4/realm/token";
		long tm= System.currentTimeMillis()/1000 ;
		System.out.println("iat="+Long.toString(tm));
		System.out.println("exp="+Long.toString(tm+3600));
		claimArray[3] = Long.toString(  tm+ 3600);
		claimArray[4] = Long.toString(  tm);
		MessageFormat claims;
		claims = new MessageFormat(claimTemplate);
		String payload = claims.format(claimArray);

		BASE64Encoder b64Encoder = new BASE64Encoder();
		
		//Add the encoded claims object
		//token.append(Base64.encodeBase64URLSafeString(payload.getBytes("UTF-8")));
		token.append(b64Encoder.encode(payload.getBytes("UTF-8")));

		//Load the private key from a keystore
		//KeyStore keystore = KeyStore.getInstance("JKS");
		//keystore.load(new FileInputStream("./path/to/keystore.jks"), "keystorepassword".toCharArray());
		//PrivateKey privateKey = (PrivateKey) keystore.getKey("certalias", "privatekeypassword".toCharArray());

		PrivateKey privateKey = createPrivateKey();

		//Sign the JWT Header + "." + JWT Claims Object
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(token.toString().getBytes("UTF-8"));
		String signedPayload = b64Encoder.encode(signature.sign());

		//Separate with a period
		token.append(".");

		//Add the encoded signature
		token.append(signedPayload);

		System.out.println(token.toString());

		} catch (Exception e) {
		e.printStackTrace();
		}


	}
	
	//This is just for example. In real project, you should get and store your private key in  your server and submit publickey to lenovo id.
	static PrivateKey createPrivateKey(){
		  PublicKey publicKey=null;	 
		  PrivateKey privateKey=null;
		
		  KeyPairGenerator keyGen=null;
		  try {
		    keyGen=KeyPairGenerator.getInstance("RSA");
		  } catch (NoSuchAlgorithmException e) {
		    // TODO Auto-generated catch block
		    e.printStackTrace();
		  }
		  int keysize=1024;	
		  keyGen.initialize(keysize);	
		  KeyPair keyPair=keyGen.generateKeyPair();
		  privateKey=keyPair.getPrivate();
		  publicKey=keyPair.getPublic();
		  return privateKey;
	}

}

package com.bhn.jca;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Formatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMAC {
	
	private static String HMACSHA256 = "HMacSha256";
	private static String UTF8 = "UTF-8";
	
	private static String SECRET = "adfafd14234";  // for test purposes
	
	public static void main(String[] args){
		
		System.out.println(checkNull(null));
		System.out.println(checkNull(""));
		System.out.println(checkNull("C"));
		
		try {
			String hmac = (byteToB64(getHmacSHA256(SECRET, "this is my message.")));
			System.out.println(validateHmacString(SECRET, "this is my message.", hmac));
			System.out.println(validateHmacString(SECRET, null, hmac));
			System.out.println(validateHmacString(null, "this is my message.", hmac));
			System.out.println(validateHmacString(SECRET, "this is my message.", null));
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		
	}
	
	private static byte[] getHmacSHA256(String key, String message)  
            throws NoSuchAlgorithmException, UnsupportedEncodingException,  
            InvalidKeyException {  
        Mac mac = Mac.getInstance(HMACSHA256);  
        SecretKeySpec secret = new SecretKeySpec(  
                key.getBytes(UTF8), mac.getAlgorithm());  
        mac.init(secret);  
        return mac.doFinal(message.getBytes());  
    } 
	
	
	
	
	public static String bytesToHexString(byte[] bytes) {
	    StringBuilder sb = new StringBuilder(bytes.length * 2);
	 
	    Formatter formatter = new Formatter(sb);
	    for (byte b : bytes) {
	        formatter.format("%02x", b);
	    }
	    formatter.close();
	    return sb.toString();
	}
	
	
	public static String byteToB64(byte[] bytes){
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	public static boolean validateHmacString(String key, String message, String hmac) {
		boolean status = false;
		if(checkNull(key) || checkNull(message) || checkNull(hmac)){
			return status;
		}
		
		String hmacCalculated = null;;
		try {
			hmacCalculated = byteToB64(getHmacSHA256(key, message));
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| UnsupportedEncodingException e) {
			// log error
			e.printStackTrace();
		}
		if(hmac.equals(hmacCalculated)){
			status = true;
		}
		return status;
	}
	
	private static boolean checkNull(String msg){
		return msg == null  ? true : (msg.length() == 0 ? true : false);
	}

}


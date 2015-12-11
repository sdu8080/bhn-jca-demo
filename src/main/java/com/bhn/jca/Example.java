package com.bhn.jca;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Example {
	public static void main(String[] args){
		
		try {
			// Hash example using SHA
			byte i1 = 'a';
			byte i2 = 'b';
			byte i3 = 'c';
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			System.out.println(sha.getProvider());
			sha.update(i1);
			sha.update(i2);
			sha.update(i3);
			
			byte[] hash = sha.digest();
			
			System.out.println(hash.toString());
			
			// key pair example
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
			
			KeyPair pair = keyGen.generateKeyPair();
			
			System.out.println(pair.getPrivate().hashCode());
			System.out.println(pair.getPublic());
			
			
			// signing and verify signature examples
			byte[] data = "this is secret message.".getBytes();
			Signature dsa = Signature.getInstance("SHA1withDSA");
			/* Initializing the object with a private key */
			PrivateKey priv = pair.getPrivate();
			dsa.initSign(priv);

			/* Update and sign the data */
			dsa.update(data);
			byte[] sig = dsa.sign();
			System.out.println("signiture:"+sig.toString());
			
			// verify the signiture using public key
			/* Initializing the object with the public key */
			PublicKey pub = pair.getPublic();
			dsa.initVerify(pub);

			/* Update and verify the data */
			dsa.update(data);
			boolean verifies = dsa.verify(sig);
			System.out.println("signature verifies: " + verifies);
			
			
			// encryption/decryption example
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
		    SecretKey aesKey = keygen.generateKey();
		    
		    Cipher aesCipher;

		    // Create the cipher
		    aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		    
		    // Initialize the cipher for encryption
		    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

		    // Our cleartext
		    byte[] cleartext = "This is a secret message.".getBytes();

		    // Encrypt the cleartext
		    byte[] ciphertext = aesCipher.doFinal(cleartext);
		    System.out.println(ciphertext.toString());

		    // Initialize the same cipher for decryption
		    aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

		    // Decrypt the ciphertext
		    byte[] cleartext1 = aesCipher.doFinal(ciphertext);
		    System.out.println("original:"+new String(cleartext));
		    System.out.println("decrpted:"+new String(cleartext1));
		    
		    // test
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}

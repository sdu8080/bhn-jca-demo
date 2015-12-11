package com.bhn.jasypt;

import org.jasypt.util.password.StrongPasswordEncryptor;

public class SimpleTest {
	
	/*
	 * default StringPasswordEncryptor is using SHA-256 with random SALT, perform hash calculation 
	 * for 100000 times, and append the salt to the digest (first 16 bytes, or 8 chars)
	 */
	
	public static void main(String[] args){
		String password = "mypassowrd";
		StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();
		
		
		String encryptedPassword = passwordEncryptor.encryptPassword(password);
		
		if (passwordEncryptor.checkPassword(password, encryptedPassword)) {
			  System.out.println("password valid");
			} else {
			  System.out.println("password invalide");
			}
	}
}

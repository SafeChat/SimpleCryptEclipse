package de.zakath.simplecrypt;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class PBKDF2
{
			
	public static Key deriveKey(char[] password, byte[] salt, int keysize)
			throws InvalidKeySpecException, NoSuchAlgorithmException
	{
		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec ks = new PBEKeySpec(password, salt, 128, keysize);
		SecretKey s = f.generateSecret(ks);
		Key k = new SecretKeySpec(s.getEncoded(), "AES");
		return k;
	}

	public static Key deriveKey(char[] password, int keysize)
	{

	}

	
	
}

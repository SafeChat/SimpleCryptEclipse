package de.zakath.simplecrypt;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class PBKDF2
{

	public static Key deriveKey(char[] password, byte[] salt, int keysize)
	{
		try
		{
			SecretKeyFactory f = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
			KeySpec ks = new PBEKeySpec(password, salt, 128, keysize);
			SecretKey s = f.generateSecret(ks);
			Key k = new SecretKeySpec(s.getEncoded(), "AES");
			return k;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException ex)
		{
			return null;
		}
	}

	public static Key deriveKey(char[] password, int keysize)

	{
		try
		{
			SecretKeyFactory f = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
			KeySpec ks = new PBEKeySpec(password, computeSalt(password), 128,
					keysize);
			SecretKey s = f.generateSecret(ks);
			Key k = new SecretKeySpec(s.getEncoded(), "AES");
			return k;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | UnsupportedEncodingException ex)
		{
			return null;
		}

	}

	private static byte[] computeSalt(char[] password)
			throws UnsupportedEncodingException
	{
		byte[] salt = new String(password).getBytes("UTF-8");
		for (int i = 0; i < password.length; i++)
		{
			salt = SHA256.computeHash(salt);
		}
		return salt;
	}

}

package de.zakath.simplecrypt;

import java.security.*;

public class SHA256
{

	public static byte[] computeHash(byte[] input)
	{
		try
		{
			return MessageDigest.getInstance("SHA-256").digest(input);
		} catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}

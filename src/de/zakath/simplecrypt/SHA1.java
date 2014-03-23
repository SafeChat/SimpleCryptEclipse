/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.zakath.simplecrypt;

import java.security.*;

/**
 * 
 * @author cw
 */
public class SHA1
{

	/**
	 * Computes the SHA1 hash of a given byte array.
	 * 
	 * @param input
	 *            The byte array, the hash should be computed from.
	 * @return The computed hash.
	 */
	public static byte[] computeHash(byte[] input)
	{
		try
		{
			return MessageDigest.getInstance("SHA-1").digest(input);
		} catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}

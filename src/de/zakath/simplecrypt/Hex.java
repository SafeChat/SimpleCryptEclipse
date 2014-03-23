/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.zakath.simplecrypt;

/**
 * 
 * @author cw
 */
public class Hex
{

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String encode(byte[] input)
	{
		char[] hexChars = new char[input.length * 2];
		for (int j = 0; j < input.length; j++)
		{
			int v = input[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static byte[] decode(String input)
	{
		int len = input.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2)
		{
			data[i / 2] = (byte) ((Character.digit(input.charAt(i), 16) << 4) + Character
					.digit(input.charAt(i + 1), 16));
		}
		return data;
	}

}

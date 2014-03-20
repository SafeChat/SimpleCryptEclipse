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
public class Base64
{

    public static String encode(byte[] input)
    {
        return com.sun.org.apache.xerces.internal.impl.dv.util.Base64.encode(input);
    }

    public static byte[] decode(String input)
    {
        return com.sun.org.apache.xerces.internal.impl.dv.util.Base64.decode(input);
    }
}

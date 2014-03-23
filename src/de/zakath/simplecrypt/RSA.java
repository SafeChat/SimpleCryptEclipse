/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.zakath.simplecrypt;

import java.security.*;
import java.util.logging.*;
import javax.crypto.*;

/**
 * 
 * @author cw
 */
public class RSA
{

	/**
	 * The key size used for key creation
	 */
	public static final int KEYSIZE = 2048;

	protected static final SecureRandom rnd = new SecureRandom();

	protected KeyPair _keypair;
	protected RSA _rsa;

	/**
	 * Creates a new instance of the RSA algorithm with the given keypair.
	 * 
	 * @param keypair
	 *            The keypair used for this algorithm.
	 */
	public RSA(KeyPair keypair)
	{
		_keypair = keypair;
	}

	/**
	 * Creates a new instance of the RSA algorithm with the given privatekey and
	 * publickey.
	 * 
	 * @param publickey
	 *            The publickey used for this algorithm.
	 * @param privatekey
	 *            The privatekey used for this alogithm.
	 */
	public RSA(PublicKey publickey, PrivateKey privatekey)
	{
		this(new KeyPair(publickey, privatekey));
	}

	/**
	 * Creates a new instance of the RSA algorithm with the given publickey.
	 * 
	 * @param publickey
	 *            The publickey used for this algorithm.
	 */
	public RSA(PublicKey publickey)
	{
		this(publickey, null);
	}

	/**
	 * Creates a new instance of the RSA algorithm with the given privatekey.
	 * 
	 * @param privatekey
	 *            The privatekey used for this alogithm.
	 */
	public RSA(PrivateKey privatekey)
	{
		this(null, privatekey);
	}

	/**
	 * Sets the keypair used for this alogrithm.
	 * 
	 * @param keypair
	 *            The keypair that should be set.
	 */
	public void setKeyPair(KeyPair keypair)
	{
		_keypair = keypair;
	}

	/**
	 * Gets the keypair currently used.
	 * 
	 * @return The currently used keypair.
	 */
	public KeyPair getKeyPair()
	{
		return _keypair;
	}

	/**
	 * Creates a new keypair with a private and a publickey. Default size is
	 * 2048 bits
	 * 
	 * @return The new generated keypair
	 */
	public static KeyPair createKeyPair()
	{
		try
		{
			KeyPairGenerator pairgen = KeyPairGenerator
					.getInstance("RSA", "BC");
			pairgen.initialize(KEYSIZE, rnd);
			return pairgen.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException ex)
		{
			Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}

	}

	/**
	 * Signs a byte array with the private key, which is set for this instance.
	 * 
	 * @param input
	 *            The byte array that should be signed
	 * @return The signed byte array. It consists of 256 bits signature followed
	 *         by the data given to this method.
	 */
	public byte[] sign(byte[] input)
	{
		try
		{
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(_keypair.getPrivate());
			signature.update(input);
			byte[] sign = signature.sign();
			byte[] output = new byte[sign.length + input.length];

			System.arraycopy(sign, 0, output, 0, sign.length);
			System.arraycopy(input, 0, output, sign.length, input.length);

			return output;
		} catch (NoSuchAlgorithmException
				| InvalidKeyException
				| SignatureException ex)
		{
			Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}

	}

	/**
	 * Verifys a sign byte array
	 * 
	 * @param input
	 *            The signed byte array. First 256 byte must be signature,
	 *            followed byte signed data
	 * @return A verifyresult, consisting of a boolean indicating if verfiying
	 *         was successful and a byte array containig the data which was
	 *         singed. For more informations see {@link VerifyResult}.
	 * 
	 */
	public VerifyResult verify(byte[] input)
	{
		VerifyResult result;

		try
		{
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(_keypair.getPublic());

			byte[] sign = new byte[256];
			byte[] data = new byte[input.length - 256];

			System.arraycopy(input, 0, sign, 0, 256);
			System.arraycopy(input, 256, data, 0, input.length - 256);

			signature.update(data);
			result = new VerifyResult(signature.verify(sign), data);
		} catch (NoSuchAlgorithmException
				| InvalidKeyException
				| SignatureException ex)
		{
			Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
			result = new VerifyResult(false, null);
		}
		return result;
	}

	/**
	 * Encrypts a byte array with the public key set for this instance.
	 * 
	 * @param input
	 *            The byte array that should be encrypted. Be aware: Maximum
	 *            size is 245 bits by a key size of 2048 bits which is default!
	 * @return The encrypted byte array.
	 */
	public byte[] encrypt(byte[] input)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA/None/pkcs1padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, _keypair.getPublic());
			return cipher.doFinal(input);
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| InvalidKeyException
				| IllegalBlockSizeException
				| BadPaddingException
				| NoSuchProviderException ex)
		{
			Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}
	}

	/**
	 * Decrypts a byte array with the private key set for this instance.
	 * 
	 * @param input
	 *            The byte array that should be decrypted.
	 * @return The decrypted byte array.
	 */
	public byte[] decrypt(byte[] input)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA/None/pkcs1padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, _keypair.getPrivate());
			return cipher.doFinal(input);
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| InvalidKeyException
				| IllegalBlockSizeException
				| BadPaddingException
				| NoSuchProviderException ex)
		{
			Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}
	}

	/**
	 * A class, representing the result of a verification.
	 */
	public class VerifyResult
	{

		private boolean _verifyed = false;

		/**
		 * Indicates whether the verification was successful or not.
		 * 
		 * @return The boolean value.
		 */
		public boolean isVerifyed()

		{
			return _verifyed;
		}

		private byte[] _data;

		/**
		 * The byte array which was singed without the signature bytes.
		 * 
		 * @return The byte array.
		 */
		public byte[] Data()
		{
			return _data;
		}

		/**
		 * Creates a new instance of VerifyResult.
		 * 
		 * @param wasSuccessful
		 *            A boolean which indicates whether the verification was
		 *            successful or not.
		 * @param data
		 *            A byte array which holds signed data without singed bytes.
		 */
		public VerifyResult(boolean wasSuccessful, byte[] data)
		{
			_verifyed = wasSuccessful;
			_data = data;
		}
	}
}

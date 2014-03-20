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
public class CombiCrypt
{

    protected RSA _rsa;

    /**
     * Creates a new instance of the CombiCrypt algorithm with the given
     * keypair.
     *
     * @param keypair The keypair used for this algorithm.
     */
    public CombiCrypt(KeyPair keypair)
    {
        _rsa = new RSA(keypair);
    }

    /**
     * Get the underlaying instance of the RSA algorithm
     *
     * @return The instance of the RSA algorithm
     */
    public RSA getRSA()
    {
        return _rsa;
    }

    /**
     * Creates a new instance of the CombiCrypt algorithm with the given
     * privatekey and publickey.
     *
     * @param publickey The publickey used for this algorithm.
     * @param privatekey The privatekey used for this alogithm.
     */
    public CombiCrypt(PublicKey publickey, PrivateKey privatekey)
    {
        this(new KeyPair(publickey, privatekey));
    }

    /**
     * Creates a new instance of the CombiCrypt algorithm with the given
     * publickey.
     *
     * @param publickey The publickey used for this algorithm.
     */
    public CombiCrypt(PublicKey publickey)
    {
        this(publickey, null);
    }

    /**
     * Creates a new instance of the CombiCrypt algorithm with the given
     * privatekey.
     *
     * @param privatekey The privatekey used for this alogithm.
     */
    public CombiCrypt(PrivateKey privatekey)
    {
        this(null, privatekey);
    }

    /**
     * Sets the keypair used for this alogrithm.
     *
     * @param keypair The keypair that should be set.
     */
    public void setKeyPair(KeyPair keypair)
    {
        _rsa.setKeyPair(keypair);
    }

    /**
     * Gets the keypair currently used.
     *
     * @return The currently used keypair.
     */
    public KeyPair getKeyPair()
    {
        return _rsa.getKeyPair();
    }

    /**
     * Encrypts a byte array using a randomly generated key for AES encryption
     * and encrypts this key with the given public key.
     *
     * @param input The byte array that should be encrypted
     * @return The encrypted byte array. First 256 bits is the, with the public
     * key, encryptet key which was used for encription of the main data.
     */
    public byte[] encrypt(byte[] input)
    {
        byte[] key = new byte[245];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(key);

        byte[] rsapart = _rsa.encrypt(key);
        byte[] aespart = AES.encrypt(input, key);

        byte[] output = new byte[rsapart.length + aespart.length];

        System.arraycopy(rsapart, 0, output, 0, rsapart.length);
        System.arraycopy(aespart, 0, output, rsapart.length, aespart.length);
        return output;
    }

    /**
     * Decrypts a byte array using a key with is crypted stored into it
     *
     * @param input The byte array that should be decrypted
     * @return The encrypted byte array
     */
    public byte[] decrypt(byte[] input)
    {
        byte[] key = new byte[256];
        byte[] data = new byte[input.length - 256];

        System.arraycopy(input, 0, key, 0, 256);
        System.arraycopy(input, 256, data, 0, input.length - 256);

        byte[] decryptedkey = _rsa.decrypt(key);

        return AES.decrypt(data, decryptedkey);
    }

}

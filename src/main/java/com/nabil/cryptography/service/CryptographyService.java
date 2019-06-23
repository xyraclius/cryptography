package com.nabil.cryptography.service;

import java.io.File;

public interface CryptographyService {
    byte[] encrypt(byte[] plainText, String publicKey);

    byte[] decrypt(byte[] plainText, String privateKeyString, String passPhrase);

    void encrypt(File plainFile, File chiperFileDestination, String publicKey);

    void decrypt(File chiperFile, File plainFileDestination, String privateKey, String passPhrase);
}

package com.nabil.cryptography.service.impl;

import com.nabil.cryptography.service.CryptographyService;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

@Service
public class CryptographyServiceImpl implements CryptographyService {

    private String tempFolder;

    public CryptographyServiceImpl() {
        Security.addProvider(new BouncyCastleProvider());
    }

    static PGPPublicKey getPublicKey(String armoredString) {
        PGPPublicKey key = null;
        try {
            InputStream in = new ByteArrayInputStream(armoredString.getBytes());
            in = PGPUtil.getDecoderStream(in);

            JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);
            in.close();
            Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
            while (key == null && rIt.hasNext()) {
                PGPPublicKeyRing kRing = rIt.next();
                Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
                while (key == null && kIt.hasNext()) {
                    PGPPublicKey k = kIt.next();

                    if (k.isEncryptionKey()) {
                        key = k;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    @Override
    public byte[] encrypt(byte[] data, String publicKey) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = null;
        try {
            pOut = lData.open(bOut,
                    PGPLiteralData.BINARY,
                    PGPLiteralData.CONSOLE,
                    data.length,
                    new Date());
            pOut.write(data);
            pOut.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (pOut != null)
                try {
                    pOut.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream cOut = null;
        try {
            byte[] plainText = bOut.toByteArray();

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));

            PGPPublicKey pgpPublicKey = getPublicKey(publicKey);
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));

            cOut = encGen.open(encOut, plainText.length);
            cOut.write(plainText);
        } catch (Exception e) {
            throw new SecurityException(e);
        } finally {
            if (cOut != null)
                try {
                    cOut.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
        return encOut.toByteArray();
    }

    @Override
    public byte[] decrypt(byte[] plainText, String privateKeyString, String passPhrase) {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(plainText);
        byte[] data = new byte[0];
        try {
            PGPEncryptedDataList encList = null;
            encList = (PGPEncryptedDataList) pgpFact.nextObject();

            PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

            PGPPrivateKey privateKey = getPrivateKey(privateKeyString, passPhrase);
            PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider("BC")
                    .build(privateKey);

            InputStream clear = encData.getDataStream(dataDecryptorFactory);

            byte[] literalData = Streams.readAll(clear);

            if (encData.verify()) {
                PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
                PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
                data = Streams.readAll(litData.getInputStream());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }

    @Override
    public void encrypt(File plainFile, File chiperFileDestination, String publicKey) {

        Date dateNow = new Date();
        tempFolder = System.getProperty("user.home");

        File tmpFolder = new File(tempFolder);
        if (!tmpFolder.isDirectory()) {
            tmpFolder.mkdirs();
        }

        String stagingTmpFileName = tempFolder + File.separator + "stagingTmpFilePgp_" + dateNow.getTime() + ".tmp";
        File stagingTmpFile = new File(stagingTmpFileName);

        FileOutputStream bOut = null;
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = null;

        try {
            stagingTmpFile.createNewFile();
            bOut = new FileOutputStream(stagingTmpFile);

            pOut = lData.open(bOut,
                    PGPLiteralData.BINARY,
                    PGPLiteralData.CONSOLE,
                    plainFile.length(),
                    dateNow);
            Files.copy(plainFile.toPath(), pOut);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (pOut != null)
                try {
                    pOut.close();
                    bOut.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }

        OutputStream cOut = null;
        FileOutputStream encOut = null;
        RandomAccessFile rafStg = null;
        PGPEncryptedDataGenerator encGen = null;
        try {

            encOut = new FileOutputStream(chiperFileDestination);

            encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));

            PGPPublicKey pgpPublicKey = getPublicKey(publicKey);
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));


            cOut = encGen.open(encOut, stagingTmpFile.length());

            {

                rafStg = new RandomAccessFile(stagingTmpFile, "r");
                final int bufferSize = 1048576;
                boolean continued = true;
                long cycle = 0;

                while (continued) {
                    byte[] buffer = new byte[bufferSize];

                    rafStg.seek(cycle * bufferSize);
                    int numberOfReadBytes = rafStg.read(buffer, 0, bufferSize);

                    if (numberOfReadBytes < bufferSize) {
                        continued = false;

                        byte[] newBuffer = new byte[numberOfReadBytes];
                        newBuffer = Arrays.copyOf(buffer, newBuffer.length);

                        buffer = newBuffer;
                    }

                    cOut.write(buffer);
                    cycle++;
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (encGen != null)
                    encGen.close();

                if (cOut != null)
                    cOut.flush();
                cOut.close();

                if (encOut != null)
                    encOut.flush();
                encOut.close();

                if (rafStg != null)
                    rafStg.close();

                Files.delete(stagingTmpFile.toPath());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void decrypt(File chiperFile, File plainFileDestination, String privateKeyString, String passPhrase) {
                try {
                FileOutputStream fos = new FileOutputStream(plainFileDestination);
                InputStream in = new FileInputStream(chiperFile);
                Security.addProvider(new BouncyCastleProvider());
                in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
                PGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
                PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
                PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
                PGPPrivateKey privateKey = getPrivateKey(privateKeyString, passPhrase);
                PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC")
                        .build(privateKey);

                InputStream clear = encData.getDataStream(dataDecryptorFactory);

            PGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                 pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                InputStream unc = ld.getInputStream();
                int ch;

                while ((ch = unc.read()) >= 0) {
                    fos.write(ch);
                }
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }

        } catch (Exception e){
            e.printStackTrace();
        }

    }

    static PGPPrivateKey getPrivateKey(String armoredString, String passphrase) {
        PGPPrivateKey key = null;
        try {
            InputStream in = new ByteArrayInputStream(armoredString.getBytes());
            in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

            JcaPGPSecretKeyRingCollection pgpPub = new JcaPGPSecretKeyRingCollection(in);
            in.close();

            PGPDigestCalculatorProvider digestCalc = new JcaPGPDigestCalculatorProviderBuilder().build();

            Provider provider = new BouncyCastleProvider();
            PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(digestCalc)
                    .setProvider(provider)
                    .build(passphrase.toCharArray());

            Iterator<PGPSecretKeyRing> rIt = pgpPub.getKeyRings();
            while (key == null && rIt.hasNext()) {

                PGPSecretKeyRing kRing = rIt.next();
                PGPSecretKey sec = kRing.getSecretKey();

                Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();
                while (key == null && kIt.hasNext()) {
                    PGPSecretKey k = kIt.next();

                    if (k.isMasterKey()) {
                        key = sec.extractPrivateKey(decryptor);
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }


}

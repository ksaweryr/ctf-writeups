using System;
using System.IO;
using Microsoft.Research.SEAL;

class Program {
    // Copied from decompiled Client.exe
    static SecretKey ParseBase64EncodedSecretKeyToSecretKey(string raw) {
        EncryptionParameters encryptionParameters = new EncryptionParameters(SchemeType.BFV);
        ulong polyModulusDegree = (encryptionParameters.PolyModulusDegree = 4096uL);
        encryptionParameters.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
        encryptionParameters.PlainModulus = new Modulus(512uL);
        SEALContext context = new SEALContext(encryptionParameters);
        MemoryStream stream = new MemoryStream(Convert.FromBase64String(raw));
        SecretKey secretKey = new SecretKey();
        secretKey.Load(context, stream);
        return secretKey;
    }

    // Copied from decompiled Client.exe
    static PublicKey ParseBase64EncodedPublicKeyToPublicKey(string base64EncodedPublicKey) {
        EncryptionParameters encryptionParameters = new EncryptionParameters(SchemeType.BFV);
        ulong polyModulusDegree = (encryptionParameters.PolyModulusDegree = 4096uL);
        encryptionParameters.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
        encryptionParameters.PlainModulus = new Modulus(512uL);
        SEALContext context = new SEALContext(encryptionParameters);
        MemoryStream stream = new MemoryStream(Convert.FromBase64String(base64EncodedPublicKey));
        PublicKey publicKey = new PublicKey();
        publicKey.Load(context, stream);
        return publicKey;
    }

    // Copied from decompiled Client.exe
    static Ciphertext ParseBase64EncodedCiphertextToCiphertext(string base64EncodedCiphertext) {
        EncryptionParameters encryptionParameters = new EncryptionParameters(SchemeType.BFV);
        ulong polyModulusDegree = (encryptionParameters.PolyModulusDegree = 4096uL);
        encryptionParameters.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
        encryptionParameters.PlainModulus = new Modulus(512uL);
        SEALContext context = new SEALContext(encryptionParameters);
        MemoryStream stream = new MemoryStream(Convert.FromBase64String(base64EncodedCiphertext));
        Ciphertext ciphertext = new Ciphertext(context);
        ciphertext.Load(context, stream);
        return ciphertext;
    }

    public static void Main(string[] args) {
        // Load secret and public keys from provided files
        SecretKey secretKey = ParseBase64EncodedSecretKeyToSecretKey(File.ReadAllText("secretkey.key"));
        PublicKey publicKey = ParseBase64EncodedPublicKeyToPublicKey(File.ReadAllText("publickey.key"));

        // Create a decryptor
        BFVEncryptionProvider bFVEncryptionProvider = new BFVEncryptionProvider();
        Decryptor decryptor = new Decryptor(bFVEncryptionProvider.Context, secretKey);

        // Read and parse latitude and longitude from files
        Ciphertext encryptedLat = ParseBase64EncodedCiphertextToCiphertext(File.ReadAllText("latitude.txt"));
        Ciphertext encryptedLon = ParseBase64EncodedCiphertextToCiphertext(File.ReadAllText("longitude.txt"));

        // Decrypt the coordinates
        Plaintext lat = new Plaintext();
        Plaintext lon = new Plaintext();
        decryptor.Decrypt(encryptedLon, lat);
        decryptor.Decrypt(encryptedLat, lon);
        Console.WriteLine(lat);
        Console.WriteLine(lon);
    }
}

// Copied from decompiled Client.exe (but removed context's getter to replace it with public property getter)
class BFVEncryptionProvider {
	public SEALContext Context { get; private set; }

	public BFVEncryptionProvider() {
		EncryptionParameters encryptionParameters = new EncryptionParameters(SchemeType.BFV);
		encryptionParameters.CoeffModulus = CoeffModulus.BFVDefault(encryptionParameters.PolyModulusDegree = 4096uL);
		encryptionParameters.PlainModulus = new Modulus(512uL);
		Context = new SEALContext(encryptionParameters);
	}
}
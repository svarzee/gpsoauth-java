package svarzee.gps.gpsoauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static java.lang.String.format;

class CipherUtil {
  public byte[] createSignature(String username, String password, BigInteger modulus, BigInteger exponent) {
    try (ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
      bytes.write(0);
      bytes.write(Arrays.copyOfRange(sha1(createKeyStruct(modulus, exponent)), 0, 4));
      bytes.write(pkcs1AoepEncode(format("%s\0%s", username, password).getBytes(), createKey(modulus, exponent)));
      return bytes.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private byte[] pkcs1AoepEncode(byte[] bytes, PublicKey publicKey) {
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      return cipher.doFinal(bytes);
    } catch (InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException e) {
      throw new IllegalStateException(e);
    }
  }

  private PublicKey createKey(BigInteger modulus, BigInteger exponent) {
    try {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
      return factory.generatePublic(keySpec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private byte[] sha1(byte[] bytes) {
    try {
      return MessageDigest.getInstance("SHA1").digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private byte[] createKeyStruct(BigInteger modulus, BigInteger exponent) {
    try (ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
      bytes.write(new byte[]{0x00, 0x00, 0x00, (byte) 0x80});
      bytes.write(bigIntegerToBytesWithoutSign(modulus));
      bytes.write(new byte[]{0x00, 0x00, 0x00, 0x03});
      bytes.write(bigIntegerToBytesWithoutSign(exponent));
      return bytes.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private byte[] bigIntegerToBytesWithoutSign(BigInteger bigInteger) {
    byte[] bytes = bigInteger.toByteArray();
    return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
  }
}

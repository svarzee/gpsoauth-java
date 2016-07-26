package svarzee.gps.gpsoauth;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Properties;

class GpsoauthConfig {
  private final BigInteger modulus;
  private final BigInteger exponent;

  GpsoauthConfig(String configFile) {
    Properties properties = getProperties();
    this.modulus = new BigInteger(properties.getProperty("modulus"));
    this.exponent = new BigInteger(properties.getProperty("exponent"));
  }

  private Properties getProperties() {
    try (final InputStream stream = this.getClass().getClassLoader().getResourceAsStream("gpsoauth.properties")) {
      final Properties properties = new Properties();
      properties.load(stream);
      return properties;
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public BigInteger getModulus() {
    return modulus;
  }

  public BigInteger getExponent() {
    return exponent;
  }
}

package svarzee.gps.gpsoauth;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

class GpsoauthConfig {
  final String modulus;
  final String exponent;

  GpsoauthConfig(String configFile) {
    Properties properties = getProperties();
    this.modulus = properties.getProperty("modulus");
    this.exponent = properties.getProperty("exponent");
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

  public String getModulus() {
    return modulus;
  }

  public String getExponent() {
    return exponent;
  }
}

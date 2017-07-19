package svarzee.gps.gpsoauth.config;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Properties;

public class GpsoauthConfigFileFactory implements GpsoauthConfigFactory {

  private final String configFile;

  public GpsoauthConfigFileFactory(String configFile) {
    this.configFile = configFile;
  }

  @Override
  public GpsoauthConfig load() {
    return fromFile(configFile);
  }

  private GpsoauthConfig fromFile(String configFile) {
    Properties properties = getProperties(configFile);
    BigInteger modulus = new BigInteger(properties.getProperty("modulus"));
    BigInteger exponent = new BigInteger(properties.getProperty("exponent"));
    String userAgent = properties.getProperty("user-agent");
    return new GpsoauthConfig(modulus, exponent, userAgent);
  }

  private Properties getProperties(String configFile) {
    try (final InputStream stream = this.getClass().getClassLoader().getResourceAsStream(configFile)) {
      final Properties properties = new Properties();
      properties.load(stream);
      return properties;
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

}

package svarzee.gps.gpsoauth.config;

import java.math.BigInteger;

public class GpsoauthConfig {
  private final BigInteger modulus;
  private final BigInteger exponent;
  private final String userAgent;

  public GpsoauthConfig(BigInteger modulus, BigInteger exponent, String userAgent) {
    this.modulus = modulus;
    this.exponent = exponent;
    this.userAgent = userAgent;
  }

  public BigInteger getModulus() {
    return modulus;
  }

  public BigInteger getExponent() {
    return exponent;
  }

  public String getUserAgent() {
    return userAgent;
  }
}

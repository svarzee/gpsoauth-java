package svarzee.gps.gpsoauth.config;

import java.math.BigInteger;

public class GpsoauthConfig {
  private final BigInteger modulus;
  private final BigInteger exponent;

  public GpsoauthConfig(BigInteger modulus, BigInteger exponent) {
    this.modulus = modulus;
    this.exponent = exponent;
  }


  public BigInteger getModulus() {
    return modulus;
  }

  public BigInteger getExponent() {
    return exponent;
  }
}

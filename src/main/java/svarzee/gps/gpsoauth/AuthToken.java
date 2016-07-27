package svarzee.gps.gpsoauth;

public class AuthToken {
  private final String token;
  private final long expiry;

  public AuthToken(String token, long expiry) {

    this.token = token;
    this.expiry = expiry;
  }

  public String getToken() {
    return token;
  }

  public long getExpiry() {
    return expiry;
  }
}

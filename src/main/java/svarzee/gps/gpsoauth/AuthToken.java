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

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null || getClass() != obj.getClass()) return false;

    AuthToken authToken = (AuthToken) obj;

    if (expiry != authToken.expiry) return false;
    return token != null ? token.equals(authToken.token) : authToken.token == null;
  }

  @Override
  public int hashCode() {
    int result = token != null ? token.hashCode() : 0;
    result = 31 * result + (int) (expiry ^ (expiry >>> 32));
    return result;
  }

  @Override
  public String toString() {
    return "AuthToken{"
        + "token='" + token + '\''
        + ", expiry=" + expiry
        + '}';
  }
}

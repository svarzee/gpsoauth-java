package svarzee.gps.gpsoauth;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Base64;

import static java.lang.Long.parseLong;

public class Gpsoauth {

  private final CipherUtil cipherUtil = new CipherUtil();
  private final GpsoauthConfig config = new GpsoauthConfig("gpsoauth.properties");
  private final String userAgent;

  private final OkHttpClient httpClient;

  public Gpsoauth(OkHttpClient httpClient) {
    this(httpClient, "gpsoauth/0.1");
  }

  public Gpsoauth(OkHttpClient httpClient, String userAgent) {
    this.httpClient = httpClient;
    this.userAgent = userAgent;
  }

  public AuthToken login(String username,
                         String password,
                         String androidId,
                         String service,
                         String app,
                         String clientSig) throws IOException, TokenRequestFailed {
    String masterToken = performMasterLoginForToken(username, password, androidId);
    return performOAuthForToken(username, masterToken, androidId, service, app, clientSig);
  }

  public Response performMasterLogin(String username, String password, String androidId) throws IOException {
    return performMasterLogin(
        username, password, androidId, "ac2dm", "us", "us", "en", "17"
    );
  }

  public Response performMasterLogin(String username,
                                     String password,
                                     String androidId,
                                     String service,
                                     String deviceCountry,
                                     String operatorCountry,
                                     String lang,
                                     String sdkVersion) throws IOException {
    byte[] signature = cipherUtil
        .createSignature(
            username,
            password,
            config.getModulus(),
            config.getExponent()
        );
    String b64Signature = Base64.getUrlEncoder().encodeToString(signature);

    FormBody formBody = new FormBody.Builder()
        .add("accountType", "HOSTED_OR_GOOGLE")
        .add("Email", username)
        .add("has_permission", "1")
        .add("add_account", "1")
        .add("EncryptedPasswd", b64Signature)
        .add("service", service)
        .add("source", "android")
        .add("androidId", androidId)
        .add("device_country", deviceCountry)
        .add("operatorCountry", operatorCountry)
        .add("lang", lang)
        .add("sdk_version", sdkVersion)
        .build();

    Request request = new Request.Builder()
        .url("https://android.clients.google.com/auth")
        .post(formBody)
        .header("User-Agent", userAgent)
        .build();

    return httpClient.newCall(request).execute();
  }

  public String performMasterLoginForToken(String username, String password, String androidId) throws IOException, TokenRequestFailed {
    return performMasterLoginForToken(
        username, password, androidId, "ac2dm", "us", "us", "en", "17"
    );
  }

  public String performMasterLoginForToken(String username,
                                           String password,
                                           String androidId,
                                           String service,
                                           String deviceCountry,
                                           String operatorCountry,
                                           String lang,
                                           String sdkVersion) throws IOException, TokenRequestFailed {
    Response response = performMasterLogin(
        username, password, androidId, service, deviceCountry, operatorCountry, lang, sdkVersion
    );
    String responseStr = response.body().string();
    if (response.code() != 200 || !responseStr.contains("Token=")) throw new TokenRequestFailed();
    return responseStr.replaceAll("(\n|.)*?Token=(.*)?\n(\n|.)*", "$2");
  }

  public Response performOAuth(String username,
                               String masterToken,
                               String androidId,
                               String service,
                               String app,
                               String clientSig) throws IOException {
    return performOAuth(
        username, masterToken, androidId, service, app, clientSig, "us", "us", "en", "17"
    );
  }

  public Response performOAuth(String username,
                               String masterToken,
                               String androidId,
                               String service,
                               String app,
                               String clientSig,
                               String deviceCountry,
                               String operatorCountry,
                               String lang,
                               String sdkVersion) throws IOException {
    OkHttpClient httpClient = new OkHttpClient();

    FormBody formBody = new FormBody.Builder()
        .add("accountType", "HOSTED_OR_GOOGLE")
        .add("Email", username)
        .add("has_permission", "1")
        .add("EncryptedPasswd", masterToken)
        .add("service", service)
        .add("source", "android")
        .add("androidId", androidId)
        .add("app", app)
        .add("client_sig", clientSig)
        .add("device_country", deviceCountry)
        .add("operatorCountry", operatorCountry)
        .add("lang", lang)
        .add("sdk_version", sdkVersion)
        .build();

    Request request = new Request.Builder()
        .url("https://android.clients.google.com/auth")
        .post(formBody)
        .header("User-Agent", userAgent)
        .build();

    return httpClient.newCall(request).execute();
  }

  public AuthToken performOAuthForToken(String username,
                                        String masterToken,
                                        String androidId,
                                        String service,
                                        String app,
                                        String clientSig) throws IOException, TokenRequestFailed {
    return performOAuthForToken(
        username, masterToken, androidId, service, app, clientSig, "us", "us", "en", "17"
    );
  }

  public AuthToken performOAuthForToken(String username,
                                        String masterToken,
                                        String androidId,
                                        String service,
                                        String app,
                                        String clientSig,
                                        String deviceCountry,
                                        String operatorCountry,
                                        String lang,
                                        String sdkVersion) throws IOException, TokenRequestFailed {
    Response response = performOAuth(
        username, masterToken, androidId, service, app, clientSig, deviceCountry, operatorCountry, lang, sdkVersion
    );
    String responseStr = response.body().string();
    if (response.code() != 200 || !responseStr.contains("Auth=")) throw new TokenRequestFailed();
    String token = responseStr.replaceAll("(\n|.)*?Auth=(.*)?\n(\n|.)*", "$2");
    String expiry = responseStr.replaceAll("(\n|.)*?Expiry=(.*)?\n(\n|.)*", "$2");
    return new AuthToken(token, parseLong(expiry));
  }

  public static class TokenRequestFailed extends Exception {
  }
}

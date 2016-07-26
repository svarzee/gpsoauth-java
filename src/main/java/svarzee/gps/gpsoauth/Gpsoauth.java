package svarzee.gps.gpsoauth;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Base64;

public class Gpsoauth {

  private final CipherUtil cipherUtil = new CipherUtil();
  private final GpsoauthConfig config = new GpsoauthConfig("gpsoauth.properties");

  private final OkHttpClient httpClient;

  public Gpsoauth(OkHttpClient httpClient) {
    this.httpClient = httpClient;
  }

  public String login(String username, String password) throws IOException, TokenRequestFailed {
    String masterToken = performMasterLoginForToken(username, password);
    return performOAuthForToken(username, masterToken);
  }

  public Response performMasterLogin(String username, String password) throws IOException {
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
        .add("service", "ac2dm")
        .add("source", "android")
        .add("androidId", "9774d56d682e549c")
        .add("device_country", "us")
        .add("operatorCountry", "us")
        .add("lang", "en")
        .add("sdk_version", "17")
        .build();

    Request request = new Request.Builder()
        .url("https://android.clients.google.com/auth")
        .post(formBody)
        .header("User-Agent", "gpsoauth/0.1")
        .build();

    return httpClient.newCall(request).execute();
  }

  public String performMasterLoginForToken(String username, String password) throws IOException, TokenRequestFailed {
    Response response = performMasterLogin(username, password);
    String responseStr = response.body().string();
    if (response.code() != 200 || !responseStr.contains("Token=")) throw new TokenRequestFailed();
    return responseStr.replaceAll("(\n|.)*?Token=(.*)?\n(\n|.)*", "$2");
  }

  public Response performOAuth(String username, String masterToken) throws IOException {
    OkHttpClient httpClient = new OkHttpClient();

    FormBody formBody = new FormBody.Builder()
        .add("accountType", "HOSTED_OR_GOOGLE")
        .add("Email", username)
        .add("has_permission", "1")
        .add("EncryptedPasswd", masterToken)
        .add("service", "audience:server:client_id:848232511240-7so421jotr2609rmqakceuu1luuq0ptb.apps.googleusercontent.com")
        .add("source", "android")
        .add("androidId", "9774d56d682e549c")
        .add("app", "com.nianticlabs.pokemongo")
        .add("client_sig", "321187995bc7cdc2b5fc91b11a96e2baa8602c62")
        .add("device_country", "us")
        .add("operatorCountry", "us")
        .add("lang", "en")
        .add("sdk_version", "17")
        .build();

    Request request = new Request.Builder()
        .url("https://android.clients.google.com/auth")
        .post(formBody)
        .header("User-Agent", "gpsoauth/0.3.0")
        .build();

    return httpClient.newCall(request).execute();
  }

  public String performOAuthForToken(String username, String masterToken) throws IOException, TokenRequestFailed {
    Response response = performOAuth(username, masterToken);
    String responseStr = response.body().string();
    if (response.code() != 200 || !responseStr.contains("Auth=")) throw new TokenRequestFailed();
    return responseStr.replaceAll("(\n|.)*?Auth=(.*)?\n(\n|.)*", "$2");
  }

  public static class TokenRequestFailed extends Exception {
  }
}

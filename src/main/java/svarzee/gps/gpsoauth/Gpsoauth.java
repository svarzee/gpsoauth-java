package svarzee.gps.gpsoauth;

import java.io.IOException;
import java.lang.reflect.Field;
import javax.net.ssl.X509TrustManager;

import net.iharder.Base64;
import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.TlsVersion;
import svarzee.gps.gpsoauth.config.GpsoauthConfig;
import svarzee.gps.gpsoauth.config.GpsoauthConfigFactory;
import svarzee.gps.gpsoauth.config.GpsoauthConfigFileFactory;
import xxx.sun.security.ssl.SSLSocketFactoryImpl;

import static java.lang.Long.parseLong;
import static java.util.Collections.singletonList;
import static net.iharder.Base64.URL_SAFE;

public class Gpsoauth {

  private final Util util;
  private final CipherUtil cipherUtil;
  private final GpsoauthConfig config;
  private final OkHttpClient httpClient;

  private static <T> T readFieldOrNull(Object instance, Class<T> fieldType, String fieldName) {
    for (Class<?> c = instance.getClass(); c != Object.class; c = c.getSuperclass()) {
      try {
        Field field = c.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object value = field.get(instance);
        if (!fieldType.isInstance(value)) return null;
        return fieldType.cast(value);
      } catch (NoSuchFieldException ignored) {
        // ignore
      } catch (Exception e) {
        throw new AssertionError();
      }
    }
    if (!fieldName.equals("delegate")) {
      Object delegate = readFieldOrNull(instance, Object.class, "delegate");
      if (delegate != null) return readFieldOrNull(delegate, fieldType, fieldName);
    }

    return null;
  }

  public static ConnectionSpec compatibleConnectionSpec() {
    return new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .cipherSuites(
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA
        )
        .tlsVersions(TlsVersion.TLS_1_2)
        .supportsTlsExtensions(true)
        .build();
  }

  public static SSLSocketFactoryImpl compatibleSslFactory() {
    SSLSocketFactoryImpl sslSocketFactory;
    try {
      sslSocketFactory = new SSLSocketFactoryImpl();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to create SSLSocketFactoryImpl.");
    }
    return sslSocketFactory;
  }

  public static X509TrustManager compatibleTrustManager(SSLSocketFactoryImpl compatibleSslFactory) {
    try {
      Class<?> sslContextClass = Class.forName("xxx.sun.security.ssl.SSLContextImpl");
      Object context = readFieldOrNull(compatibleSslFactory, sslContextClass, "context");
      if (context == null) throw new IllegalStateException("Failed to create X509TrustManager.");
      X509TrustManager trustManager = readFieldOrNull(context, X509TrustManager.class, "trustManager");
      if (trustManager == null) throw new IllegalStateException("Failed to create X509TrustManager.");
      return trustManager;
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException("Failed to create X509TrustManager.");
    }
  }

  private static OkHttpClient compatibleOkHttpClient() {
    SSLSocketFactoryImpl sslSocketFactory = compatibleSslFactory();
    return new OkHttpClient
        .Builder()
        .connectionSpecs(singletonList(compatibleConnectionSpec()))
        .sslSocketFactory(sslSocketFactory, compatibleTrustManager(sslSocketFactory))
        .build();
  }

  public Gpsoauth() {
    this(compatibleOkHttpClient());
  }

  public Gpsoauth(OkHttpClient httpClient) {
    this(httpClient, new GpsoauthConfigFileFactory("gpsoauth.properties"));
  }

  public Gpsoauth(OkHttpClient httpClient, GpsoauthConfigFactory gpsoauthConfigFactory) {
    this.util = new Util();
    this.cipherUtil = new CipherUtil();
    this.config = gpsoauthConfigFactory.load();
    this.httpClient = httpClient;
  }

  /**
   * If expiry is not received then its value defaults to -1.
   */
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
    String b64Signature = Base64.encodeBytes(signature, URL_SAFE);

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
        .header("User-Agent", config.getUserAgent())
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
    try (Response response = performMasterLogin(username, password, androidId, service, deviceCountry, operatorCountry, lang, sdkVersion)) {
      if (response.code() != 200) throw new TokenRequestFailed();
      String responseBody = response.body().string();
      Try<String> token = util.extractValue(responseBody, "Token");
      if (token.isFailure()) throw new TokenRequestFailed();
      else return token.get();
    }
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
        .header("User-Agent", config.getUserAgent())
        .build();

    return httpClient.newCall(request).execute();
  }

  /**
   * If expiry is not received then its value defaults to -1.
   */
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

  /**
   * If expiry is not received then its value defaults to -1.
   */
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
    try (Response response = performOAuth(
        username, masterToken, androidId, service, app, clientSig, deviceCountry, operatorCountry, lang, sdkVersion
    )) {
      if (response.code() != 200) throw new TokenRequestFailed();
      String responseBody = response.body().string();
      Try<String> token = util.extractValue(responseBody, "Auth");
      Try<String> expiry = util.extractValue(responseBody, "Expiry");
      if (token.isFailure()) throw new TokenRequestFailed();
      return new AuthToken(token.get(), expiry.isFailure() ? -1 : parseLong(expiry.get()));
    }
  }

  public static class TokenRequestFailed extends Exception {
  }
}

Java client library for Google Play Services OAuth
--------------------------------------------------

Based on [gpsoauth](https://github.com/simon-weber/gpsoauth) by [Simon Weber](https://github.com/simon-weber).

With this library you can log in using username and password.

You can link the library in your dependencies manager by following instructions on [https://jitpack.io/#svarzee/gpsoauth-java](https://jitpack.io/#svarzee/gpsoauth-java).

Simplest usage:
```
AuthToken token = new Gpsoauth().login("username", "password", "androidId", "service", "app", "clientSig");
```
Known issues
------------
It seems google is very strict about SSL communication and any changes to it make it fail.

It is recommended to use `Gpsoauth.compatibleOkHttpClient` to create `OkHttpClient` instance with proper SSL settings.

Using jdk other than hotspot 1.8.0_231 or openjdk 1.8.0_212 may introduce SSL implementation problems.

Using okhttp other than 3.4.1. 3.5.0, 3.6.0 may introduce SSL implementation problems.

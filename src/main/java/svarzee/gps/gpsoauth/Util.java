package svarzee.gps.gpsoauth;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static svarzee.gps.gpsoauth.Try.failure;

class Util {
  public Try<String> extractValue(String responseBody, String key) {
    Matcher matcher = Pattern.compile(format("(\n|^)%s=(.*)?(\n|$)", key)).matcher(responseBody);
    if (matcher.find()) return Try.of(matcher.group(2));
    else return failure();
  }
}

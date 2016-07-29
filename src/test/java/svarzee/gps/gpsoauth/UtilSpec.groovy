package svarzee.gps.gpsoauth

import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import static svarzee.gps.gpsoauth.Try.failure

@Unroll
class UtilSpec extends Specification {

    @Shared
    Util util = new Util()

    def "should extract value from response body"(String responseBody) {
        expect:
        util.extractValue(responseBody, "expected_value_key").get() == "expected_value"
        where:
        responseBody << [
                "expected_value_key=expected_value",
                "expected_value_key=expected_value\nsome_key=some_val",
                "some_key=some_val\nexpected_value_key=expected_value",
                "some_key_1=some_val_1\nexpected_value_key=expected_value\nsome_key_2=some_val_2",
                "a=b\nc=d\ne=f\nexpected_value_key=expected_value\ng=h\ni=j\nk=n",
        ]
    }

    def "should extract value from very long response body"(String responseBody) {
        expect:
        util.extractValue(responseBody, "expected_value_key").get() == "expected_value"
        where:
        responseBody << [
                (1..10000).collect({ "key_$it=val_$it" }).join("\n") +
                        "\nexpected_value_key=expected_value\n" +
                        (10001..20000).collect({ "key_$it=val_$it" }).join("\n"),
                (1..10000).collect({ "key_part_$it" }).join("\n") +
                        "=" + (10001..20000).collect({ "val_part_$it" }).join("\n") +
                        "\nexpected_value_key=expected_value",
        ]
    }


    def "should fail extracting value when value is not present"(String responseBody) {
        expect:
        util.extractValue(responseBody, "expected_value_key") == failure()
        where:
        responseBody << [
                "other_key=other_val",
                "some_body"
        ]
    }
}

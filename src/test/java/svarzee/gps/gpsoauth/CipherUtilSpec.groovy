package svarzee.gps.gpsoauth

import spock.lang.Shared
import spock.lang.Specification

class CipherUtilSpec extends Specification {

    @Shared
    def cipherUtil = new CipherUtil()
    @Shared
    def config = new GpsoauthConfig("gpsoauth.properties")

    def "should not fail when creating a signature"() {
        when:
        cipherUtil.createSignature("some", "fake", config.modulus, config.exponent)
        then:
        noExceptionThrown()
    }

    def "should create a signature that is 133 bytes long and starts with a 0 byte"() {
        when:
        def signature = cipherUtil.createSignature("username", "password", config.modulus, config.exponent)
        then:
        signature.length == 133
        signature[0] == 0 as byte
    }
}

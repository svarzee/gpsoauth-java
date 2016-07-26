package svarzee.gps.gpsoauth

import spock.lang.Specification

import static svarzee.gps.gpsoauth.test.TestUtil.TEST_PROPS

class GpsoauthConfigSpec extends Specification {
    def "should load the config"() {
        given:
        def configFile = 'gpsoauth.properties'
        when:
        def config = new GpsoauthConfig(configFile)
        then:
        config.modulus == new BigInteger(TEST_PROPS.modulus)
        config.exponent == new BigInteger(TEST_PROPS.exponent)
    }

}

package svarzee.gps.gpsoauth.config

import spock.lang.Specification
import svarzee.gps.gpsoauth.test.TestUtil

class GpsoauthConfigFileFactorySpec extends Specification {
    def "should load the config"() {
        given:
        def configFile = 'gpsoauth.properties'
        when:
        def config = new GpsoauthConfigFileFactory(configFile).load()
        then:
        config.modulus == new BigInteger(TestUtil.TEST_PROPS.modulus)
        config.exponent == new BigInteger(TestUtil.TEST_PROPS.exponent)
    }
}

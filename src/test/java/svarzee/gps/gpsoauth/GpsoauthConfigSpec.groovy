package svarzee.gps.gpsoauth

import spock.lang.Specification

class GpsoauthConfigSpec extends Specification {
    def "should load the config"() {
        given:
        def configFile = 'gpsoauth.properties'
        when:
        def config = new GpsoauthConfig(configFile)
        then:
        config.modulus == BigInteger.valueOf(13)
        config.exponent == BigInteger.valueOf(7)
    }

}

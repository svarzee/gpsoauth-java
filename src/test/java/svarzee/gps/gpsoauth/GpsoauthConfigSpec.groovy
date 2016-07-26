package svarzee.gps.gpsoauth

import spock.lang.Specification

class GpsoauthConfigSpec extends Specification {
    def "should load the config"() {
        given:
        def configFile = 'gpsoauth.properties'
        when:
        def config = new GpsoauthConfig(configFile)
        then:
        config.modulus == '13'
        config.exponent == '7'
    }

}

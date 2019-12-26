package svarzee.gps.gpsoauth

import spock.lang.Shared
import spock.lang.Specification

import static svarzee.gps.gpsoauth.Gpsoauth.TokenRequestFailed
import static svarzee.gps.gpsoauth.test.TestUtil.TEST_PROPS

class GpsoauthSpec extends Specification {

    @Shared
    Gpsoauth gpsoauth = new Gpsoauth()
    @Shared
    String validUsername = TEST_PROPS.validUsername
    @Shared
    String validPassword = TEST_PROPS.validPassword
    @Shared
    String androidId = TEST_PROPS.androidId
    @Shared
    String service = TEST_PROPS.service
    @Shared
    String app = TEST_PROPS.app
    @Shared
    String clientSig = TEST_PROPS.clientSig


    def "should return 200 ok for master login with valid credentials"() {
        when:
        def response = gpsoauth.performMasterLogin(validUsername, validPassword, androidId)
        then:
        response.code() == 200
    }

    def "should return response with `Token` value for master login with valid credentials"() {
        when:
        def response = gpsoauth.performMasterLogin(validUsername, validPassword, androidId)
        then:
        response.body().string().contains("Token=")
    }

    def "should return 403 forbidden for master login with invalid credentials"() {
        when:
        def response = gpsoauth.performMasterLogin("some_invalid_username", "some_invalid_password", androidId)
        then:
        response.code() == 403
    }

    def "should throw TokenRequestFailed for master login token request with invalid credentials"() {
        when:
        gpsoauth.performMasterLoginForToken("some_invalid_username", "some_invalid_password", androidId)
        then:
        thrown(TokenRequestFailed)
    }

    def "should get a master token"() {
        when:
        def token = gpsoauth.performMasterLoginForToken(validUsername, validPassword, androidId)
        then:
        !token.isEmpty()
    }

    def "should return 200 ok for oauth with valid master token"() {
        given:
        def masterToken = gpsoauth.performMasterLoginForToken(validUsername, validPassword, androidId)
        when:
        def response = gpsoauth.performOAuth(validUsername, masterToken, androidId, service, app, clientSig)
        then:
        response.code() == 200
    }

    def "should return response with `Auth` and `Expiry` values for oauth with valid master token"() {
        given:
        def masterToken = gpsoauth.performMasterLoginForToken(validUsername, validPassword, androidId)
        when:
        def response = gpsoauth.performOAuth(validUsername, masterToken, androidId, service, app, clientSig)
        def bodyStr = response.body().string()
        then:
        bodyStr.contains("Auth=")
        bodyStr.contains("Expiry=")
    }

    def "should return 403 forbidden for oath with invalid master token"() {
        when:
        def response = gpsoauth.performOAuth(validUsername, "some_invalid_master_token", androidId, service, app, clientSig)
        then:
        response.code() == 403
    }

    def "should throw TokenRequestFailed for oath token request with invalid master token"() {
        when:
        gpsoauth.performOAuthForToken(validUsername, "some_invalid_master_token", androidId, service, app, clientSig)
        then:
        thrown(TokenRequestFailed)
    }
}

package svarzee.gps.gpsoauth.test

class TestUtil {
    static final Properties TEST_PROPS
    static {
        TEST_PROPS = new Properties()
        TestUtil.class
                .getClassLoader()
                .getResourceAsStream("gpsoauth.properties")
                .withStream({ TEST_PROPS.load(it) })
    }
}

final class NegativeItem {
    int read() {
        return 1;
    }
}

public class Negative {
    static NegativeItem directValue(NegativeItem value) {
        return value;
    }

    static java.lang.reflect.Method variableReflection(String name) throws Exception {
        return NegativeItem.class.getDeclaredMethod(name);
    }
}

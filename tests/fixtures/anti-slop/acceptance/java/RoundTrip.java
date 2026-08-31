final class Item {
    int read() {
        return 1;
    }
}

public class RoundTrip {
    static Item objectCastRoundTrip(Item value) {
        return (Item) (Object) value;
    }

    static java.lang.reflect.Method literalReflection() throws Exception {
        return Item.class.getDeclaredMethod("read");
    }

    static Item directValue(Item value) {
        return value;
    }
}

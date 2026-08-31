using System;

public sealed class Item
{
    public void Read() { }
}

public static class RoundTrip
{
    public static Item ObjectCastRoundTrip(Item value)
    {
        return (Item)(object)value;
    }

    public static System.Reflection.MethodInfo LiteralReflection()
    {
        return typeof(Item).GetMethod("Read")!;
    }

    public static Item DirectValue(Item value)
    {
        return value;
    }
}

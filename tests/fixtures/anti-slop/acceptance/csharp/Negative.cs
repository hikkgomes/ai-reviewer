using System;

public sealed class NegativeItem
{
    public void Read() { }
}

public static class Negative
{
    public static NegativeItem DirectValue(NegativeItem value)
    {
        return value;
    }

    public static System.Reflection.MethodInfo VariableReflection(string name)
    {
        return typeof(NegativeItem).GetMethod(name)!;
    }
}

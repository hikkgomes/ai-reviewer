package acceptance

type Other struct {
	Value int
}

func NoRoundTrip(value Other) Other {
	return value
}

func ExplicitAssertion(value any) Other {
	return value.(Other)
}

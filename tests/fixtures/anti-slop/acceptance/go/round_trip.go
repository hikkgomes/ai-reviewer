package acceptance

import "reflect"

type Item struct {
	Value int
}

func InterfaceRoundTrip(value Item) Item {
	return any(value).(Item)
}

func ReflectInterfaceRoundTrip(value Item) Item {
	return reflect.ValueOf(value).Interface().(Item)
}

func DirectValue(value Item) Item {
	return value
}

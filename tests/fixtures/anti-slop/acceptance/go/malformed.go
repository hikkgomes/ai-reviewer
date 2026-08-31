//go:build acceptance_malformed

package acceptance

func Broken(value Item) Item {
	return any(value).(Item)

package acceptance

type GeneratedItem struct{}

func Generated(value GeneratedItem) GeneratedItem {
	return any(value).(GeneratedItem)
}

typedef struct Item {
    int value;
} Item;

int void_pointer_round_trip(Item *value) {
    return ((Item *)(void *)value)->value;
}

int direct_value(Item *value) {
    return value->value;
}

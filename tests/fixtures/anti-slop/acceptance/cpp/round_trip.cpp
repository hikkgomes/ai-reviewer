struct Item {
    int value;
};

Item *redundant_cast(Item *value) {
    return static_cast<Item *>(reinterpret_cast<Item *>(value));
}

Item *void_pointer_chain(Item *value) {
    return static_cast<Item *>(static_cast<void *>(value));
}

Item *direct_value(Item *value) {
    return value;
}

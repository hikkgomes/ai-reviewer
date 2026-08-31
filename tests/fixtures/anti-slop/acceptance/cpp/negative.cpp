struct Other {
    int value;
};

Other *different_cast(Other *value) {
    return static_cast<Other *>(value);
}

Other *direct_value(Other *value) {
    return value;
}

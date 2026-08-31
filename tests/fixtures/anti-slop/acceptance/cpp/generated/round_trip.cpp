struct Generated {
    int value;
};

Generated *generated(Generated *value) {
    return static_cast<Generated *>(static_cast<void *>(value));
}

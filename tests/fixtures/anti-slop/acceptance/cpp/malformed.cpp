struct Broken {
    int value;

Broken *broken(Broken *value) {
    return static_cast<Broken *>(static_cast<void *>(value));
}

typedef struct Broken {
    int value;
int broken(Broken *value) {
    return ((Broken *)(void *)value)->value;
}

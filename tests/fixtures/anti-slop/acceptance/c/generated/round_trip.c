typedef struct Generated {
    int value;
} Generated;

int generated(Generated *value) {
    return ((Generated *)(void *)value)->value;
}

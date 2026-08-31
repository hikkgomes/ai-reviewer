typedef struct Other {
    int value;
} Other;

int no_round_trip(Other *value) {
    return value->value;
}

int explicit_cast(Other *value) {
    return ((Other *)value)->value;
}

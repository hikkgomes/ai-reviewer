// Perform the required operation.
saveUser(user)

// The transaction can retry, so external side effects must run after commit.
commit()

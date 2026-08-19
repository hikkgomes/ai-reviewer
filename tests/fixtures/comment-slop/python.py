# Update the user's name
user.name = name

# The transaction can retry, so external side effects must run after commit.
commit()

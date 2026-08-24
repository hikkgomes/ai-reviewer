// Check if the user exists
if (user) {
  // Update the user's name
  user.name = name;
}

// Keep the old slug because external webhook signatures include it.
const slug = existingSlug;

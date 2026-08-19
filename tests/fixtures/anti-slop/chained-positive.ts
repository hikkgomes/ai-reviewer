declare const input: unknown;
type User = { id: string };
const user = input as object as User;
export { user };

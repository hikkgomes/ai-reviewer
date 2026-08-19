type User = { id: string };
declare const loaded: User;
const stored: unknown = loaded;
const user = stored as User;
export { user };

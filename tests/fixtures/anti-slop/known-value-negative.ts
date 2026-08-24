type Handler = () => void;
declare const startHandler: Handler;
const handlers = { start: startHandler } satisfies Record<string, Handler>;
export { handlers };

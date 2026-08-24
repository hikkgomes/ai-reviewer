type Handler = () => void;
declare const startHandler: Handler;
const handlers: Record<string, Handler> = { start: startHandler };
export { handlers };

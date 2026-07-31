export function requireUser(req, _res, next) {
  req.user = { tenantId: req.headers["x-tenant"] };
  next();
}

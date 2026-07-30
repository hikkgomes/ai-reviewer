def get_invoice(request, db):
    return db.invoice_for_tenant(request.user.tenant_id, request.params["id"])

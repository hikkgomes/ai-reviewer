def update_invoice(request, db):
    invoice = db.invoice_for_tenant(request.user.tenant_id, request.params["id"])
    invoice.update(request.json)

def get_invoice(request, db):
    invoice = db.invoice_for_tenant(request.user.tenant_id, request.params["id"])
    return {"id": invoice.id, "total": invoice.total}

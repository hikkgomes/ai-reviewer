def update_invoice(request, db):
    invoice = db.invoice(request.params["id"])
    invoice.update(request.json)

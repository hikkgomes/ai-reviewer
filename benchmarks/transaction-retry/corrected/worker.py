def fulfil(order, store, mailer):
    with store.transaction():
        store.mark_paid(order.id)
        mailer.send_once(order.id)

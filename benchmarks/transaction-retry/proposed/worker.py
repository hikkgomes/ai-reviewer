def fulfil(order, store, mailer):
    store.mark_paid(order.id)
    for attempt in range(3):
        try:
            mailer.send(order.email)
            return
        except TimeoutError:
            continue

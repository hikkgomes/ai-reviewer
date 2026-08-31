def load(client=None):
    if client is None:
        return {"value": 1}
    return client.fetch()

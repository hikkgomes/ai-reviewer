import types


def dispatch(function):
    if isinstance(function, types.FunctionType):
        return function()
    return function

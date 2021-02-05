VERBOSITY = 3
COLOR_VERBOSE = False


def log(verbosity, *args, **kwargs):
    suppress = kwargs.pop('suppress', False)
    color = kwargs.pop('color', None)
    if not suppress and verbosity <= VERBOSITY:
        if COLOR_VERBOSE and color:
            print(color, " " * (4 * verbosity), *args, "\033[0m", **kwargs)
        else:
            print(" " * (4 * verbosity), *args, **kwargs)

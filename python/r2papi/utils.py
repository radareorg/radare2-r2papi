def r2_is_valid(r2):
    try:
        r2.cmd("px 1")
        return True
    except IOError:
        return False

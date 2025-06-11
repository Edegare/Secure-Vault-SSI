def mkpair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y


def unpair(xy):
    """extrai componentes de um par codificado com 'mkpair'"""
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2: len_x + 2]
    y = xy[len_x + 2:]
    return x, y


def decouple(pubkey_sig_cert):
    pubkey, sig_cert = unpair(pubkey_sig_cert)
    sig, cert = unpair(sig_cert)
    return pubkey, sig, cert


def couple(pubkey, sig, cert):
    sig_cert = mkpair(sig, cert)
    pubkey_sig_cert = mkpair(pubkey, sig_cert)
    return pubkey_sig_cert


def pretty_print_message(content: str):
    lines = content.splitlines()
    max_length = max(len(line) for line in lines)
    horizontal_border = "| " + "-" * max_length + " |"

    print("content:")
    print(horizontal_border)
    for line in lines:
        print(f"| {line.ljust(max_length)} |")
    print(horizontal_border)

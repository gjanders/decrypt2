import os
import sys
from collections import OrderedDict

# add the bin dir to the path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))


def test_decrypt_hexed() -> None:
    """this checks the stream function not the rest"""
    import bin.decrypt as decrypt

    streamer = decrypt.DecryptCommand()
    """ equivalent to `| decrypt field=testfield hex() emit('hexed')` """
    streamer.field = "testfield"
    streamer.fieldnames = ["hex()", "emit('hexed')"]

    records = [
        OrderedDict([("testfield", "hello"), ("_chunked_idx", "0")]),
        OrderedDict([("testfield", "world"), ("_chunked_idx", "1")]),
        OrderedDict([("_chunked_idx", "2")]),
    ]

    output = list(streamer.stream(records))
    assert output[0]["testfield"] == "hello"
    assert output[0]["hexed"] == "68656c6c6f"
    print(output[0])

    assert output[1]["testfield"] == "world"
    assert output[1]["hexed"] == "776f726c64"
    print(output[1])

    assert output[2] == {"_chunked_idx": "2"}
    print(output[2])
    assert len(output) == 3
    # ensure there's no errors
    assert not any(decrypt.FAILURE_FIELD in rec for rec in output)

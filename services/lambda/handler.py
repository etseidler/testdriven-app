import sys
from io import StringIO


def lambda_handler(event, context):
    code = event["answer"]
    test_code = code + "\nprint(sum(1,1))"
    buffer = StringIO()
    sys.stdout = buffer
    try:
        exec(test_code)
    except:
        return False
    sys.stdout = sys.stdout
    if int(buffer.getvalue()) == 2:
        return True
    return False

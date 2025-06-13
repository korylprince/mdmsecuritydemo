from flask import Flask, request
import base64
import plistlib
import json

app = Flask(__name__)

def clean_json(obj):
    if isinstance(obj, dict):
        new = dict()
        for k, v in obj.items():
            new[clean_json(k)] = clean_json(v)
        return new
    elif isinstance(obj, list):
        return [clean_json(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple([clean_json(i) for i in obj])
    elif isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except:
            return repr(obj)
    else:
        return obj

@app.route("/", methods=["POST"])
def webhook():
    r = request.json

    if "acknowledge_event" in r:
        payload = base64.b64decode(r["acknowledge_event"]["raw_payload"])
        del r["acknowledge_event"]["raw_payload"]
        r["acknowledge_event"]["payload"] = plistlib.loads(payload)

    if "checkin_event" in r:
        payload = base64.b64decode(r["checkin_event"]["raw_payload"])
        del r["checkin_event"]["raw_payload"]
        r["checkin_event"]["payload"] = plistlib.loads(payload)

    try:
        print(json.dumps(clean_json(r), indent=4))
    except:
        print(repr(clean_json(r)))
    return ""

app.run(host="0.0.0.0", port=8080)

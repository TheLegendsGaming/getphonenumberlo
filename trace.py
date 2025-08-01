import phonenumbers
from phonenumbers import geocoder

import time, random

def start_phone_tracer(target):
    print(f"[+] PhoneTracer v3.1")
    print(f"[+] Target: {target}")
    print(f"[+] Tracing..")
    time.sleep(2)
    p = phonenumbers.parse(target)
    r = geocoder.description_for_number(p,"en")
    print(f"[+] location: {r}")
    print(f"[+] Trace complete")
start_phone_tracer(input("Target Phone Number: "))

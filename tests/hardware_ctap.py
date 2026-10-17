"""USB acceptance test. Requires real USER-button presses; never bypasses presence."""
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools/python-deps"))
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.attestation import PackedAttestation
from fido2.cose import ES256
from fido2.ctap import CtapError

mode=sys.argv[1] if len(sys.argv)>1 else "info"
devices=[d for d in CtapHidDevice.list_devices() if d.descriptor.vid==0x0483 and d.descriptor.pid==0x5750]
if not devices:
    raise SystemExit("No accessible STM32 CTAP HID device found. On Windows, direct HID access may require an elevated terminal; browser WebAuthn access is separate.")
device=devices[0]
ctap=Ctap2(device)
print("GetInfo:",ctap.info,flush=True)
assert "FIDO_2_0" in ctap.info.versions
assert ctap.info.pin_uv_protocols == [1]
assert ctap.info.options.get("rk")
assert ctap.info.options.get("uv") == ctap.info.options.get("clientPin")
if mode=="info":
    device.close()
    sys.exit(0)
statefile=ROOT/"tests/results/credential.json"
statefile.parent.mkdir(parents=True,exist_ok=True)
timer_event=threading.Event()
timer=threading.Timer(40,timer_event.set)
def status(s): print("Keepalive:",s,flush=True)
if mode=="register":
    challenge=os.urandom(32)
    user_id=os.urandom(16)
    print("PRESS blue USER button when orange blinks.",flush=True)
    timer.start()
    try:
        response=ctap.make_credential(challenge,{"id":"stm32-lab.test","name":"STM32 Lab"},{"id":user_id,"name":"lab"},[{"type":"public-key","alg":-7}],options={"rk":True},event=timer_event,on_keepalive=status)
    finally: timer.cancel()
    PackedAttestation().verify(response.att_stmt,response.auth_data,challenge)
    attested=response.auth_data.credential_data
    state={"id":attested.credential_id.hex(),"user_id":user_id.hex(),"x":attested.public_key[-2].hex(),"y":attested.public_key[-3].hex()}
    statefile.write_text(json.dumps(state,indent=2))
    print("PASS: registration and packed self-attestation signature verified",flush=True)
elif mode in ("assert","discoverable"):
    state=json.loads(statefile.read_text())
    challenge=os.urandom(32)
    print("PRESS blue USER button when orange blinks.",flush=True)
    timer.start()
    try:
        allow_list=None if mode=="discoverable" else [{"type":"public-key","id":bytes.fromhex(state["id"])}]
        response=ctap.get_assertion("stm32-lab.test",challenge,allow_list,event=timer_event,on_keepalive=status)
    finally: timer.cancel()
    assert response.auth_data.rp_id_hash==hashlib.sha256(b"stm32-lab.test").digest()
    assert response.auth_data.counter>state.get("counter",0)
    ES256({1:2,3:-7,-1:1,-2:bytes.fromhex(state["x"]),-3:bytes.fromhex(state["y"])}).verify(bytes(response.auth_data)+challenge,response.signature)
    if mode=="discoverable":
        assert response.user and response.user["id"]==bytes.fromhex(state["user_id"])
    state["counter"]=response.auth_data.counter;statefile.write_text(json.dumps(state,indent=2))
    print("PASS: {} assertion signature and increasing persisted counter {}".format(mode,state["counter"]),flush=True)
device.close()

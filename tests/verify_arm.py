"""Run the built ARM routines in Unicorn and verify signatures independently."""
import os
import pathlib
import struct
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_DIR = pathlib.Path(os.environ.get("STM32_BUILD_DIR", ROOT / "build"))
sys.path.insert(0, str(ROOT / "tools/python-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fido2 import cbor

symbols = {}
for line in subprocess.check_output(["arm-none-eabi-nm", "-n", str(BUILD_DIR/"stm32-openfido2")], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        symbols[fields[2]] = int(fields[0], 16)
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
uc.mem_map(0x08000000, 0x100000)
uc.mem_map(0x20000000, 0x20000)
uc.mem_write(0x08000000, (BUILD_DIR/"stm32-openfido2.bin").read_bytes())
uc.mem_write(symbols["_sdata"], bytes(uc.mem_read(symbols["_etext"], symbols["_edata"]-symbols["_sdata"])))
STOP = 0x080ff000

def hook(machine, address, size, data):
    if address == STOP:
        machine.emu_stop()
    elif address == symbols["crypto_random"]:
        pointer = machine.reg_read(UC_ARM_REG_R1)
        length = machine.reg_read(UC_ARM_REG_R2)
        machine.mem_write(pointer, os.urandom(length))
        machine.reg_write(UC_ARM_REG_R0, 0)
        from unicorn.arm_const import UC_ARM_REG_PC
        machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))

uc.hook_add(UC_HOOK_CODE, hook, begin=STOP, end=STOP)
uc.hook_add(UC_HOOK_CODE, hook, begin=symbols["crypto_random"], end=symbols["crypto_random"])
def call(name, *args):
    for reg, value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3), args):
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM_REG_SP, 0x2001e000)
    uc.reg_write(UC_ARM_REG_LR, STOP|1)
    uc.emu_start(symbols[name]|1, STOP+2, count=100_000_000)
    return uc.reg_read(UC_ARM_REG_R0)

# cb_view is a two-word struct, passed in R0/R1 under ARM AAPCS.
samples = [
    (cbor.encode({1: os.urandom(32), 2: {"id": "example.test"}, 4: [{"alg": -7, "type": "public-key"}]}), True),
    (b"\xa2\x01\x00\x01\x01", False), # duplicate map key
    (b"\x18\x01", False), # non-minimal integer
    (b"\x5a\xff\xff\xff\xff", False), # oversized byte string
    (b"\x9f\xff", False), # indefinite array
]
for encoded, expected in samples:
    uc.mem_write(0x20014000, encoded)
    assert bool(call("cb_valid",0x20014000,len(encoded))) == expected
    for length in range(len(encoded)):
        assert not call("cb_valid",0x20014000,length), (encoded,length)
print("PASS: ARM CBOR valid requests, duplicate keys, truncation and length rejection")

record, x, y = 0x20014000, 0x20014200, 0x20014240
assert call("crypto_generate",record,x,y) == 1
xb, yb = bytes(uc.mem_read(x,32)), bytes(uc.mem_read(y,32))
public = ec.EllipticCurvePublicNumbers(int.from_bytes(xb,"big"),int.from_bytes(yb,"big"),ec.SECP256R1()).public_key()
message = b"authenticator test: authData plus clientDataHash"
uc.mem_write(0x20014300,message)
# Fifth argument (signature length pointer) goes on stack.
sig, slen = 0x20014400, 0x20014500
for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),(record,0x20014300,len(message),sig)):
    uc.reg_write(reg,value)
uc.reg_write(UC_ARM_REG_SP,0x2001e000)
uc.mem_write(0x2001e000,struct.pack("<I",slen))
uc.reg_write(UC_ARM_REG_LR,STOP|1)
uc.emu_start(symbols["crypto_sign"]|1,STOP+2,count=100_000_000)
assert uc.reg_read(UC_ARM_REG_R0)==1
size=struct.unpack("<I",uc.mem_read(slen,4))[0]
signature=bytes(uc.mem_read(sig,size))
public.verify(signature,message,ec.ECDSA(hashes.SHA256()))
print("PASS: built ARM P-256 key generation and DER ECDSA signature verified with host cryptography")
print("Boundary: emulator supplies randomness; physical RNG and flash persistence require hardware checks.")

# Exercise the compiled CTAP2 handlers too, with explicit simulated presence and
# an in-memory flash commit. These substitutions never enter the firmware image.
from unicorn.arm_const import UC_ARM_REG_PC
flash_cursor=0x080e0000
presence_take_count=0
uc.mem_write(flash_cursor,b"\xff"*0x20000)
def services(machine,address,size,data):
    global flash_cursor,presence_take_count
    if address in (symbols["credential_save"],symbols["credential_save_resident"]):
        pointer=machine.reg_read(UC_ARM_REG_R0)
        record=bytearray(machine.mem_read(pointer,144))
        if address==symbols["credential_save_resident"]:
            user_pointer=machine.reg_read(UC_ARM_REG_R1)
            user_len=machine.reg_read(UC_ARM_REG_R2)
            resident_slot=(flash_cursor-0x080e0000)//144
            resident=bytearray(144)
            struct.pack_into("<II",resident,0,0x32525346,resident_slot)
            resident[8:40]=record[8:40]
            resident[40:40+user_len]=bytes(machine.mem_read(user_pointer,user_len))
            struct.pack_into("<I",resident,104,user_len)
            resident[108:140]=__import__("hashlib").sha256(resident[:108]).digest()
            struct.pack_into("<I",resident,140,0x434f4d54)
            machine.mem_write(flash_cursor,bytes(resident));flash_cursor+=144
            sequence=0x80000000|resident_slot
        else:
            sequence=struct.unpack_from("<I",record,4)[0]
            if not (sequence&0x80000000):
                sequence=(flash_cursor-0x080e0000)//144
        struct.pack_into("<II",record,0,0x32444946,sequence)
        record[108:140]=__import__("hashlib").sha256(record[:108]).digest()
        struct.pack_into("<I",record,140,0x434f4d54)
        machine.mem_write(flash_cursor,bytes(record));flash_cursor+=144
        machine.reg_write(UC_ARM_REG_R0,1)
    elif address==symbols["presence_take"]:
        presence_take_count+=1
        machine.reg_write(UC_ARM_REG_R0,1)
    else:
        machine.reg_write(UC_ARM_REG_R0,0)
    machine.reg_write(UC_ARM_REG_PC,machine.reg_read(UC_ARM_REG_LR))
for name in ("credential_save","credential_save_resident","presence_begin","presence_take","presence_cancel","indicators_result","log_puts","platform_millis"):
    uc.hook_add(UC_HOOK_CODE,services,begin=symbols[name],end=symbols[name])
def command(cmd,body):
    encoded=bytes([cmd])+cbor.encode(body)
    uc.mem_write(0x20015000,encoded)
    n=call("ctap2_dispatch",0x20015000,len(encoded),0x20016000,1200)
    if not n:
        n=call("ctap2_poll",0x20016000,1200)
    result=bytes(uc.mem_read(0x20016000,n))
    assert result and result[0]==0,result.hex()
    return cbor.decode(result[1:])
uc.mem_write(0x20015000,b"\x04")
info_len=call("ctap2_dispatch",0x20015000,1,0x20016000,1200)
info=cbor.decode(bytes(uc.mem_read(0x20016000,info_len))[1:])
assert info[4]["rk"] is True
assert info[4]["uv"] is False and info[4]["clientPin"] is False
assert info[6]==[1]
print("PASS: GetInfo advertises resident keys and PIN protocol without claiming unconfigured UV")
challenge=os.urandom(32)
registration=command(1,{1:challenge,2:{"id":"stm32-lab.test"},3:{"id":b"test"},4:[{"type":"public-key","alg":-7}],7:{"rk":True}})
from fido2.webauthn import AuthenticatorData
from fido2.attestation import PackedAttestation
auth=AuthenticatorData(registration[2])
PackedAttestation().verify(registration[3],auth,challenge)
key=auth.credential_data.public_key
cid=auth.credential_data.credential_id
assert auth.is_user_present() and len(cid)==32
print("PASS: compiled MakeCredential CBOR response and packed self-attestation")
for expected_counter in (1,2):
    challenge=os.urandom(32)
    assertion=command(2,{1:"stm32-lab.test",2:challenge,3:[{"id":cid,"type":"public-key"}]})
    auth=AuthenticatorData(assertion[2])
    assert auth.counter==expected_counter
    key.verify(bytes(auth)+challenge,assertion[3])
print("PASS: compiled GetAssertion signatures, RP binding lookup and counter increments")
challenge=os.urandom(32)
assertion=command(2,{1:"stm32-lab.test",2:challenge})
auth=AuthenticatorData(assertion[2])
assert assertion[4]["id"]==b"test"
assert auth.counter==3
key.verify(bytes(auth)+challenge,assertion[3])
print("PASS: discoverable GetAssertion returns user handle and valid signature")
presence_checks_before=presence_take_count
challenge=os.urandom(32)
assertion=command(2,{1:"stm32-lab.test",2:challenge,5:{"up":False}})
auth=AuthenticatorData(assertion[2])
assert not auth.is_user_present()
assert presence_take_count==presence_checks_before
assert auth.counter==4
key.verify(bytes(auth)+challenge,assertion[3])
print("PASS: GetAssertion up=false skips presence and clears the UP flag")
def rejected(cmd,body,expected):
    encoded=bytes([cmd])+cbor.encode(body)
    uc.mem_write(0x20015000,encoded)
    n=call("ctap2_dispatch",0x20015000,len(encoded),0x20016000,1200)
    if not n: n=call("ctap2_poll",0x20016000,1200)
    assert n==1 and bytes(uc.mem_read(0x20016000,1))==bytes([expected])
rejected(2,{1:"different-rp.test",2:os.urandom(32),3:[{"id":cid,"type":"public-key"}]},0x2e)
rejected(1,{1:os.urandom(32),2:{"id":"stm32-lab.test"},3:{"id":b"test"},4:[{"type":"public-key","alg":-7}],5:[{"type":"public-key","id":cid}]},0x19)
# Reset RAM as startup does, preserving the emulated journal.
uc.mem_write(0x20000000,b"\0"*0x20000)
uc.mem_write(symbols["_sdata"],bytes(uc.mem_read(symbols["_etext"],symbols["_edata"]-symbols["_sdata"])))
challenge=os.urandom(32)
assertion=command(2,{1:"stm32-lab.test",2:challenge,3:[{"id":cid,"type":"public-key"}]})
auth=AuthenticatorData(assertion[2])
assert auth.counter==5
key.verify(bytes(auth)+challenge,assertion[3])
print("PASS: cross-RP rejection, exclusion list, RAM reset/journal recovery")

# Provision a simulated sector-10 verifier, then exercise CTAP PIN protocol 1
# and a UV-authorized MakeCredential entirely in the compiled ARM handlers.
pin=b"123456"
pin_hash=__import__("hashlib").sha256(pin).digest()[:16]
pin_prefix=struct.pack("<I",0x31504e46)+pin_hash
pin_record=pin_prefix+__import__("hashlib").sha256(pin_prefix).digest()+struct.pack("<I",0x54494d43)
uc.mem_write(0x080c0000,pin_record)
uc.mem_write(0x20015000,b"\x04")
info_len=call("ctap2_dispatch",0x20015000,1,0x20016000,1200)
info=cbor.decode(bytes(uc.mem_read(0x20016000,info_len))[1:])
assert info[4]["uv"] is True and info[4]["clientPin"] is True
agreement=command(6,{1:1,2:2})[1]
host_private=ec.generate_private_key(ec.SECP256R1())
host_public=host_private.public_key().public_numbers()
device_public=ec.EllipticCurvePublicNumbers(
    int.from_bytes(agreement[-2],"big"),int.from_bytes(agreement[-3],"big"),ec.SECP256R1()
).public_key()
shared=__import__("hashlib").sha256(host_private.exchange(ec.ECDH(),device_public)).digest()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def aes_cbc(encrypt,data):
    operation=Cipher(algorithms.AES(shared),modes.CBC(bytes(16))).encryptor() if encrypt else Cipher(algorithms.AES(shared),modes.CBC(bytes(16))).decryptor()
    return operation.update(data)+operation.finalize()
encrypted_pin_hash=aes_cbc(True,pin_hash)
token_reply=command(6,{1:1,2:5,3:agreement,6:encrypted_pin_hash})
token=aes_cbc(False,token_reply[2])
challenge=os.urandom(32)
pin_auth=__import__("hmac").new(token,challenge,"sha256").digest()[:16]
registration=command(1,{1:challenge,2:{"id":"pin-uv.test"},3:{"id":b"uv"},4:[{"type":"public-key","alg":-7}],7:{"rk":True,"uv":True},8:pin_auth,9:1})
auth=AuthenticatorData(registration[2])
assert auth.is_user_verified() and auth.is_user_present()
print("PASS: CTAP PIN protocol 1 ECDH, AES-CBC, token HMAC, and UV-authenticated registration")

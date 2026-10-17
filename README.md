# stm32-openfido2

STM32F407 FIDO2 authenticator with a USB serial development console.

Target: STM32F4Discovery, STM32F407VGT6, 8 MHz HSE, 72 MHz CPU,
48 MHz USB. USB OTG micro-AB carries composite FIDO HID and CDC ACM.
ST-LINK is used for flashing. The active driver is ST HAL/PCD and
the ST USB Device core; src/usb_otgfs.c is an inactive historical experiment.

## Build

ARM GNU GCC, CMake and Make:

```powershell
cmake -S . -B build -G "Unix Makefiles" "-DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake"
cmake --build build
```

The ELF is `build/stm32-openfido2`, with `.bin`, `.hex` and `.map` companions.
VS Code build/debug configuration is in .vscode.

## Research status

This is an experimental firmware project developed for research and educational
purposes. It is a prototype, not a hardened product; do not use it to protect
real-world accounts or store important credentials. Testing has focused on the
STM32F4Discovery target described above.

The STM32F4Discovery's onboard audio hardware is not used and is not required
for FIDO2 operation.

## Implemented behavior

- CTAPHID INIT, PING, CBOR, fragmentation/reassembly, channel validation,
  transaction timeout, keepalives and cancellation while waiting for presence.
- CTAP2 GetInfo, MakeCredential and GetAssertion using ES256 (P-256/SHA-256),
  including discoverable credentials and user-handle responses.
- CTAP2 client PIN protocol 1 with PIN-token authorization for UV-required
  MakeCredential and GetAssertion requests.
- Packed self-attestation, credential public keys in COSE format and DER signatures.
- RP-bound random 32-byte credential IDs, resident user handles, exclusion
  lists, assertion allow lists and discoverable RP lookup.
- Fresh blue USER B1/PA0 press, 30 ms debounce and 30-second presence timeout.
- Green success, red failure, orange presence prompt, blue HID activity.
- CDC diagnostic logs, including complete CTAPHID request/response payloads in
  hexadecimal, named keepalive states, console command categories and flash
  operation addresses/status registers. Dumps may contain credential IDs,
  user data, challenges and PIN-protocol ciphertext.
- CDC console commands for listing, raw/formatted credential dumps, deleting,
  restoring, changing discoverability, compaction and PIN setup/change/delete.
- Append-only flash credentials and monotonically increasing per-credential
  assertion counters; commit/checksum validation on load.

Discoverable credentials are supported by storing their user handles in the
append-only flash journal. PIN-based user verification uses CTAP2 PIN protocol
1; GetInfo advertises `uv: true` and `clientPin: true` only after a PIN is
configured. The serial console accepts a 4-63 digit PIN using `pin set <digits>`;
the interactive COM4 watcher masks the digits and does not capture sent input.
Only the SHA-256 PIN hash prefix is stored in flash. PIN change is also available
through CTAP2. Enterprise attestation, credential management and extensions
are not implemented.
Only one matching assertion is returned. Cancellation during the short synchronous
crypto calculation is not serviced; cancellation while awaiting the button is.
GetAssertion requests with `up: false` are honored: no button prompt is made
and the signed authenticator data has the UP flag clear. Requests with UP
enabled (or omitted) continue to require a fresh physical button press.

## Use

Windows currently assigns CDC COM4. Open it with 115200/8N1, no flow control,
DTR enabled. The baud setting is metadata for USB CDC.
The CDC console accepts CR/LF-terminated `help`, `status`, `keys list`,
`keys delete <id8> <rp8>`, `keys undelete <id8> <rp8>`,
`keys discoverable <id8> <rp8> on|off`, `keys erase-all confirm`,
`keys compact confirm`, `keys dump raw <id8> <rp8>`,
`keys dump formatted <id8> <rp8>`, `pin status`, `pin set <4-63 digits>`,
`pin change <old> <new>` and `pin delete confirm`. The `id8` and `rp8`
arguments are the eight-hex-character ID and RP fingerprints shown by
`keys list`; ambiguous fingerprint pairs are rejected. Set the PIN before
connecting the authenticator to the browser; enter that PIN when prompted.
User presence still requires the blue button. Key listing shows only short
credential-ID/RP-hash fingerprints, assertion counters, and discoverable status;
it never outputs private keys or user handles. The serial watcher masks the PIN
on screen and excludes commands typed by the user from the capture file. The
CTAPHID protocol dump does not include the plaintext PIN or private credential
keys. In contrast, `keys dump raw` and `keys dump formatted` intentionally
expose credential private scalars and stored user handles for inspection; the
COM4 watcher captures this output, so use test credentials and protect any
resulting log files.
Raw output prints exact 144-byte flash records with absolute addresses and
offsets. Formatted output decodes the credential ID, RP hash, 32-byte
big-endian private scalar, counter, stored digest and commit marker; it also
shows a matching resident record and user handle when one is present.
Console logs identify commands by category without recording PIN arguments;
flash logs report operation ranges and controller status without logging
programmed data.
Use a test relying party that accepts a roaming security key. When orange
blinks, release and press the blue USER button. Black is RESET.
After registration, try authentication with the same test account, then reset
the board and authenticate again to check persistence.

Expected logs:

```text
CTAP2 MakeCredential: waiting for blue USER button
Presence confirmed: fresh USER button press
CTAP2 presence approved; computing ES256 response
MakeCredential success: credential persisted
CTAP2 GetAssertion: waiting for blue USER button
GetAssertion success: signature and counter persisted
```

## Flash storage and development security

Per-key deletion appends a tombstone, immediately hiding the key from the
authenticator while leaving its old bytes in sector 11 until compaction or
erase-all. Undelete restores the most recent pre-deletion record. The
`keys compact confirm` command snapshots sector 11 into sector 9 before
rewriting live credentials; boot recovery restores the snapshot if power fails
mid-compaction.
`keys erase-all confirm` erases sector 11 but leaves the PIN in sector 10
unchanged. A non-discoverable credential can only be made discoverable if a
user handle for it is retained; otherwise it must be re-enrolled.

The application linker is limited to 768 KiB. Sector 10, addresses
0x080C0000..0x080DFFFF, stores the PIN verifier and is erased only when replacing
the PIN. Sector 9, addresses 0x080A0000..0x080BFFFF, is reserved as temporary
compaction snapshot storage and is cleared after completion or recovery.
Sector 11, addresses 0x080E0000..0x080FFFFF, is reserved for the credential
journal. Each credential record is 144 bytes. A successful
registration or assertion appends a record. The journal
has 910 complete slots; when full, operations fail instead of erasing credentials.
An interrupted write is skipped on the next append. Counter records commit before
the corresponding assertion response is returned. Each registration consumes
two journal slots (key and user handle); each assertion consumes one. Ordinary
application reflashes must preserve sector 11; mass erase destroys all credentials.

Keys are stored in ordinary MCU flash without encryption or readout protection.
Checksums detect incomplete/corrupt writes; they do not provide tamper resistance.
The crypto sources are the reference project's mbedTLS 2.2.1, configured narrowly
for P-256 and SHA-256. This old dependency needs replacement and security review
before real-account use. Use throwaway accounts. Debug access remains enabled.
The USB VID/PID is inherited for this lab and is not an allocation for distribution.

## Verification

tests/verify_arm.py executes compiled ARM code under Unicorn and independently
verifies public keys, DER signatures, packed attestation and assertion counters
using Python cryptography/python-fido2. It also checks CBOR truncation, duplicate
keys, non-minimal values, oversized lengths, and CTAP2 PIN protocol 1 key
agreement, PIN-token issuance, UV-authorized registration and CTAPHID channel
churn with least-recently-used idle-channel eviction. Randomness, presence and
flash commits are substituted only in this emulator test.

tests/hardware_ctap.py supports info, register, assert and discoverable. Registration
and assertion require real blue-button presses. It saves the credential ID, user
handle, public key and observed counter in tests/results. Windows may deny direct access
to the FIDO HID interface; browser WebAuthn remains the manual acceptance path.

Local test packages live in tools/python-deps (ignored by Git).
Hardware RNG, actual flash writes, reset persistence and browser registration
still need successful physical acceptance, separate from emulator results.

## Attribution and licensing

Project authors: adacsabadev, Cody (ChatGPT), and Coop (Copilot).

The project started from [avivgr/stm32-u2f](https://github.com/avivgr/stm32-u2f);
special thanks to Ron Garret, avivgr, and all contributors to that project.

The project's original code is licensed under Apache License 2.0; see
[LICENSE](./LICENSE). Third-party components retain their own licenses and
notices; see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) and the
license headers in `vendor/`.

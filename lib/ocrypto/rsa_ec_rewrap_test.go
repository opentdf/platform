package ocrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	kasRSA2048PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxiglL9UYch+/Tcx8PuU2
R1t6VccwZ8m2460Kq+p3JMydV5XeXJvjlehCxPuDDExoTtnj4fGRwNjsjj5cbJbq
929VRB2BpFLnGyX1iUGGzackXcvvvFwz0DogH1IOh0szgDGPls6BokoMRdbC9bq5
ErD1Tvg1ldZ8qKX+9HYaZJm69KkBjSZb6WzJSGk3lIUTgpa3dUkCMcpeJMR0OYpD
W6CPYrgbbGfANARZej5UguRNsADL9PiPKOdlEzdZVhblYFgGKEA37XXuCEfq1myH
XmlRmOHqMNGBziGBu1CeRL+4fbf+NykGAWQ216StbcClFXHC6G1/sFuOhFE12d+v
zQIDAQAB
-----END PUBLIC KEY-----`

	kasRSA2048PrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGKCUv1RhyH79N
zHw+5TZHW3pVxzBnybbjrQqr6nckzJ1Xld5cm+OV6ELE+4MMTGhO2ePh8ZHA2OyO
Plxslur3b1VEHYGkUucbJfWJQYbNpyRdy++8XDPQOiAfUg6HSzOAMY+WzoGiSgxF
1sL1urkSsPVO+DWV1nyopf70dhpkmbr0qQGNJlvpbMlIaTeUhROClrd1SQIxyl4k
xHQ5ikNboI9iuBtsZ8A0BFl6PlSC5E2wAMv0+I8o52UTN1lWFuVgWAYoQDftde4I
R+rWbIdeaVGY4eow0YHOIYG7UJ5Ev7h9t/43KQYBZDbXpK1twKUVccLobX+wW46E
UTXZ36/NAgMBAAECggEALOpWm4P62Yt2qmTKWNtNtVj33s+amjvvt6W2gIdR4EZ8
96hh0a4IJSeTUuELsFL1ZcIf1EwUVJkW7ZsXCgofUlyrABiMFToxZkbxY941dxIG
vTgHrDNeDznNpCvOXT5fexRAztcaLTYJmB747AgaATGZOQAr7T3D3dpacwD+NIT5
1mrXJ42F35Ep29poMvgg5BRdVptjqTu7jzcORgFQmyWolZLdJK5yk6PQTpohZgLV
bSTkadlHQdSYWsn/Zc8MoFvN5URx/3jqH5OdZ0cx/1h0nNR1Xi2ejUFFtmYgro1D
o2UYCVPzAzDqiNlANJnBrOuUXn06rbD7In+vOtSbIQKBgQDrWbHTfL1g5xAnX6Vz
RFKEIt0fdHp1mYu27ou4cXjN6OOklGc7J+X/ve0m3/JX5gTOelxkKRVLGDs07VGw
+LbiBBm/QvFxCPWKHA261EVqdYD77v7WhPgGor8jrC/2RBC/9Vz+80X4PhlWD9HO
s7bX6ZQ6BAHALssFbArDJYWV1QKBgQDXiwfEBWdRmtLlnk/+MXtxIEAgZ6RxmMFE
gCiuUkBkQjjG+VbycHVs8oreQYm7x2IrTRvA3MOxVt2/ay+aM8z9HWdFPXeZEh6U
0oCnl4DKP/HmWV89MUUFc4aTNk0vg2YNvERCUACNHTvsn7VZOSbECxVUvkX8s+im
86ha2ETWGQKBgQDWxCIXaSR0Mkc2dvzHZBicxifdFXDOshCiHatY5Aumc5iQznAp
tm4XY5zvNbuz5I6MUXLQYAEzZuhYkxxSD5TsSWupcpBbYx6WKqWI0T6LOLE8tcrN
vceMXqVoCzA1XcWfNmvnp944+4opVARUyQDYpSmDi7aBRvIzf3WOwUXXBQKBgEdX
oU5ka3o7QKr354o/XphnEFKpe2iOIwpFUTHBz8ZflONnDDxatMNG1GgUUT5yFDA4
6YLAj5VXJzaAh9UGaEcvQEtOuRNVSAICWssd/mbzG2IfGsLqV+oh/t0jEBE18MWD
FyTLziLnFjqP8jqCDC6/bGQMRqYJ9musIoFPLBmhAoGBAItIHiH3e+0aREPFN4QC
pBOmDNaSdVjh1kh5L0/Bx346fTivkzmY05kCb+c+lxI4bfpeERoWrU19OHOKMLVT
pREiRl7wx0sg0UlJmqprZK6LKuVCiy8r6qX6wGsYNbkLNiB8t0ro/f2/+FsPprUt
2qCgxkX89uyYl/aupOnlBJMk
-----END PRIVATE KEY-----`

	kasRSA3072PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvpLaaETLrAY3t0O9YVNF
fn8viEJHxIWCYr9NTOWrwJiJypYFaZcvbkEZsnPyb/utgmdtgcmqrX+MbIjBzBlL
pn8apd1R3zTh136bGMHfVl8uN5oDH1QX0QVG8NQc41cVcztCWodIR6d8fofq0b8U
4ybkzp9wNph3f7BZWA+jjY9Qka9E3MFX9tOl92LTK7pIDwl7Z8pmvi0zT/VyZAsr
MV0hz5YxsD+3l3d58JindTAeVlJ03yymuc40dvJX2TwLKxqfkrUBrGoyylflGvxx
IAAfc6rj9ViIbTc3TcbMfV4o9Hwl1WrLoddwUpSG8fWXLSF5IA8LYkcwkkvkWjau
KKpaiks3rH4QB1qKsJCmG69L5bzz015EmJnfOJsjqkYoYacsn0aiT2idrNeWdXZp
t2uDw5OY9VkES21MIN8bfdWA6gonPm4iKn5L6WltQQUQdn8vk/89AOFIbP/7e3Yv
OHrp2m+VNTqcdrgVG4sdSG0DGZNSLM5U6SHMTgoQS6TtAgMBAAE=
-----END PUBLIC KEY-----`

	kasRSA3072PrivateKey = `-----BEGIN PRIVATE KEY-----
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
Wnzkl5DShi5QHFAHEwaWZizh
-----END PRIVATE KEY-----`

	kasRSA4096PublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvvGs2QasIR8bI5zeIgLw
SEJVgjREUaUxszYS3DOyakssbPZqN+3cjFQBKgrBudcrgvMUip6WmQbMOn20t4Qp
vJJdx13GCfOxZufa9Ndo5NzKEMg4Usk5MIJxBiLOkrRRMMM5jt0GvR9H8OIfKn8A
i4ByEFUi/Jpv544qJ3cZV2j7vpDSTK9EBGhbTBa64yHBTbBkwwfLG3RriukZQYid
yEE4Bi76X1UYGWsQDHRcfT1mKlggqYxLNNYPlXjxyEqJ2nQPx02ZpP/6QeNfDLYS
3CelvfBS+bxfgUWb+FVDjlCx+pUTHwRSB0YuQ5eZqKnZcE0I6eRS5Y5xo6/s8//9
7SMUCBu95XRIT7w5RT9rlUbI2ew1LNlRR48/nR16zdf/r1xTRF3qpCtqlj6Nu1Re
ujdMzSVbLz9qkpMZbpkTALcWxj1S8XjnBiasQFMhsLA0KKV9e1OPvQqwtjOQy74w
A/lZKMd5nLgeK9jlTBf8WAbWIuRJPWGkszMN9k+YvIKUlFFKVEY4hV8VBxHHMcFZ
3l6B7cIDU1pE8gXQZeDdXF7EI3hwBPKqVrpxKC5HL26sQug9HVtZmhjUzmqxwQ13
5ZY1frdOOQ50hwy2BYBYT2CeEl2gabdkGW4z/DkaLo2g1GgJZ4flRWKLCxXg/Dlx
oPtirhPIyHBgqe3rmlJvDIsCAwEAAQ==
-----END PUBLIC KEY-----`

	kasRSA4096PrivateKey = `-----BEGIN PRIVATE KEY-----
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
T1IXp5vmOmypUj5J0znUZnrXU+CpBA==
-----END PRIVATE KEY-----`

	clientRSA2048PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06c5MJO+WuhaU40o5ueP
PFiIZZaDfr0ERWpEZ0h3EeUMvD0sqrWvmay61rLkUEaHwwYZwxQp3eJ27YSGJ0Ki
fPexijdAOQuGd51inwFSJe8AwdqNSH1NzEFsZNYSAFTU4//Qq5U+Ynwq/wUxq8p8
zJ133pTyNLiAJ7tG6J2tij87e0yr0ZDDPuKlpwdHukEnKLTZUd49Y+9Fg+HiaNh1
uUzQFOoElb4wKB58E5w5fu9X8j545OAZx4x3li0Dddn/WiF3vK4xx5LYcPNsVOcQ
lebrUSiq40m+Mh1GYycp92KrGGG0tw9lEza5F/ArQVsl6RAQ3kJ0Z9P8Qn5OgFN/
VwIDAQAB
-----END PUBLIC KEY-----`

	clientRSA2048PrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTpzkwk75a6FpT
jSjm5488WIhlloN+vQRFakRnSHcR5Qy8PSyqta+ZrLrWsuRQRofDBhnDFCnd4nbt
hIYnQqJ897GKN0A5C4Z3nWKfAVIl7wDB2o1IfU3MQWxk1hIAVNTj/9CrlT5ifCr/
BTGrynzMnXfelPI0uIAnu0bona2KPzt7TKvRkMM+4qWnB0e6QScotNlR3j1j70WD
4eJo2HW5TNAU6gSVvjAoHnwTnDl+71fyPnjk4BnHjHeWLQN12f9aIXe8rjHHkthw
82xU5xCV5utRKKrjSb4yHUZjJyn3YqsYYbS3D2UTNrkX8CtBWyXpEBDeQnRn0/xC
fk6AU39XAgMBAAECggEBAL+ujavB0j6QeeV7TRS5l85GO9kNFC++zVR0ZljHlxZ8
wyjjmkVMYCkj9t4ki4NsLN3h84jqBPSveZeoUrrRrUjSJlcPrLk9B93iioOIdbZn
Gt91qEiDOucGRT2ZZhooudl3P6t1cVdOLr5hHNgBfT7uSbYqXKSEh4P0JsbarmUp
MojXOCQ799tjg/3aSaWlTqtPAhymdCMyMuqz+Sos7J/mlrRcLRs38NcN/sUw4nj1
OsFOJWzuLjrv32FglO2wKBBZXQaDg+7Irh8V9qzo1/FH75KzVTEP8DA1bCkRJQLM
HydFxLKROzPip/qLG2Hjh5EjItJh3eqPS441prqXFOECgYEA+PUa5odlSkOBFIDO
zIiECv/exis4HYMftVI8YkVmHotLjHlGdhUBdGKrObLh0IWowHQSjKLINXDtsr0o
jTooyoCc9dYapkjBc2AE/S7cg4M42Q+3INrnxB5TjFjDaAamturtqf4Vx+zGoFJc
OMA4JMgK6LoYhlXE8gajTlNQMScCgYEA2aP4Jqhhz0HEKQcR1T/Y6VApLeYBQRY6
YOwD2PjWHSNWaGzrSGP2vbvap9B4nBOx+4R3BVFBfwRaweRiABpLf5yzMQ8w8rRA
Ukzuft7ko41+b+0taKE6bIf4K18bl+4maFWClgcx4D25rzkhwrOWnf32w49fmy2V
pAs5N85fvlECgYBp1Sh+X4h7rX6uDKPc5xva4TL+41iTky5jknYBAKeMzIJtURDX
Gc7ofxlzCcxdLLS0O6O3DWw2667gkPEwOE0m6M3Q5BeoIL28IlF8n/M2JQ6Bl+Ct
ouFryciSnRlUm587m1s1LMJtnwZBGUIDDhPP7wpULOhIEyYKDTBXF6u7eQKBgFj2
iogayihzJKD0r9hwidUNHFgTra2STXiy4Pu+857jg/2ZkC9+FS0HbeCs+bAq6NT8
F77HsTMfb43UMi8CkJvwTNsf7402GxjJM7AOon0saGOOGsKrLPuSNOJdtSTMh0yc
r41uEXgtIwq6Gs/Aoy+f0U+s+pKu9n0gzVm/dSmRAoGBAMf3fDH39RFacp97jHXW
DGPwaToLcPXp5gfWGhGjf0/gdZNyDhlRxpiUAslDZncK/oxhcGuV61T6HxmKlD/n
nRhvJIhyAK8GbpVPkBi7haNl0H5DRQBev8dVxZKg13QZGJloRNInmpDnXRBwYfqa
Ez3tJkzLH5PytDsJyreB8wZL
-----END PRIVATE KEY-----`

	clientRSA3072PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxBu04Tq3Xp4IJ/2h1hWT
VvumUMKNXJ9jpm3NUinjx6QyQazUAgMF4eNs8m8beIAMpCpYG9sS8Sc5xil3UmUn
DwhgMalDU/MxDPiTWMe6TP+DRYB6uCgvJUBz2dkaLHyQrEsOdi9auQ0p3NZzjUid
yDNQBdd2EyJYslVKuZuWiPEHsfihaJcf48mUQ+XAbu1ludClN2xGyb9bvcE8p5Ev
2lAh24U7Vln+/PEwn9nsqZ9915JZBQNsswlFl1bvFhZ80Ab0AEWGEVD9HGS32t9c
x+wVl2DXBYBnCz6Rqr2oAMPGsuBMnHxF2qBL+bmM33t52Tc/l9Etnc53l56UWvZG
t9u5kh67mNoH2Si+T7j3Saor6iAGZ7FDVrBZ7Dm/vGtYIcph3winv/hLntsPMeM3
z5+8Bqmuvt/KsKVy7L89bKGxfoY7NwwjIMfoQCJAKb72GiLJJQYVDfuhjKBCsoXR
kVskEtG/mHUmiMlRrY5fqVLBku+KgrfjyS5iBedVmpPbAgMBAAE=
-----END PUBLIC KEY-----`

	clientRSA3072PrivateKey = `-----BEGIN PRIVATE KEY-----
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
5JlSZqTeZ8u+eQGlcNonAFU=
-----END PRIVATE KEY-----`

	clientRSA4096PublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtK01xut0kOEcloZBn2Aq
4mcVfqbidyy3B4vmuybaIyZz+UYiYIKXbm4j6PN5U32tYT2WjMUj2ReSVcEZirX0
RA0n5nnif2rAyshF3PD6HOkV43XTYAano0RZf8oxow78hQBQFdGEl+yPLwclBUal
vRWjY1O5ueuehoYM99eIR0Ua+AYYlCNELsTyowuTwGBpsssQYtSiIMgtZEfrZfnA
Hv+mIjo4mwN8VKFcqEcSD8/BsBY31Jg5qcRfF2sQ3nmU4rICPc/J4o1wHDbEGQNx
NvJ41ntLLvnRtJFL9E5fD5MVB7wCOD6bdYlqectMegoFM6XPBh4KuvJ7N/mnRz4j
JOl2cwCVHdzxe12/Eoym2j2aPoDY+J1H+dCBLMfKqbDEM7Q7ORG2jZH6m2SVn6ZE
NoCpEll+lRA6p0N3dvRiCyI+HnLRjqGBaJox62+D/vYkXubaE8fyd7R1kTMkHuI1
EYHwqOnKfzb4NSCmALlwGetnzegurRec2e7jESV/5ecEbSGsq5+n5jWuJvfaBNhQ
RG1TziH0dC5JCzlJ5jfOSAMbjg18svfWyodAuPxf9QHZga0/t8JsW5QThnyJoZrq
Na1ka2d9Dn3UUkRCFfJjltIZfhaoFj98AUhWXmCwQ0atTh2AP5DI7xXhywKqqyL+
AUWCoPbjycIQvYTZzNYT4d8CAwEAAQ==
-----END PUBLIC KEY-----`

	clientRSA4096PrivateKey = `-----BEGIN PRIVATE KEY-----
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
37rhIPAoq2LDsgOaeW57z0ZQ1Hqp2g==
-----END PRIVATE KEY-----`

	kasEC256PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1eSEY/uLgliKkq0klNpznlX9LOIW
sFh+ENju5oA/vZXY4Si0sNl/t9oax+IOjm5JZZSkCDYoeelajUxpQIZgRg==
-----END PUBLIC KEY-----`

	kasEC256PrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpe8aN73TmHsOQGXO
GVGzimdlJgxs5DTqptIrvJwh626hRANCAATV5IRj+4uCWIqSrSSU2nOeVf0s4haw
WH4Q2O7mgD+9ldjhKLSw2X+32hrH4g6ObklllKQINih56VqNTGlAhmBG
-----END PRIVATE KEY-----`

	kasEC384PublicKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWt3+UR+Rpxgb5iFoukHbf9kiiTbiU2i9
jLKaLhBqSZzoM1efQvpWacbb9+r5D9Mv/y7s+ThW/2+eAKoaeDSMHhoO1gSx0YXH
ej9/CqfTpdDbm4HJi/aUJ2gLwjSrSnsj
-----END PUBLIC KEY-----`

	kasEC384PrivateKey = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDALXfz/NrisKyuyvwX7
3WLUwryz4mytjHahcDn8pxVGQDUiP0zX6B+PcCCge47+Y0WhZANiAARa3f5RH5Gn
GBvmIWi6Qdt/2SKJNuJTaL2MspouEGpJnOgzV59C+lZpxtv36vkP0y//Luz5OFb/
b54Aqhp4NIweGg7WBLHRhcd6P38Kp9Ol0NubgcmL9pQnaAvCNKtKeyM=
-----END PRIVATE KEY-----`

	kasEC521PublicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAkuuA6HDjiWUXgcaxT16GHrZIJQds
zKvJJvHYHqdHycXAEzMBwrZlwmyTDMs0zC1zKnp0KJg2oN/JEMckL/7Bj3sAybE1
wySV9zHP24bzDNpQTrnd1XJp74WNClI+m/CjGCPMZOvBPNyWf8ysTQ0jFDs98AEB
A7dBvFZL2O9lLhrUEt4=
-----END PUBLIC KEY-----`

	kasEC521PrivateKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIArPqCq8Pxh2XS0Faz
OxZ3Mznwm8rHrQU0mnrn3xlrVVQefkCEeRDmsD8wAXBdd72t3HU7HvMCqWHUhLfg
ByDKS6GhgYkDgYYABACS64DocOOJZReBxrFPXoYetkglB2zMq8km8dgep0fJxcAT
MwHCtmXCbJMMyzTMLXMqenQomDag38kQxyQv/sGPewDJsTXDJJX3Mc/bhvMM2lBO
ud3VcmnvhY0KUj6b8KMYI8xk68E83JZ/zKxNDSMUOz3wAQEDt0G8VkvY72UuGtQS
3g==
-----END PRIVATE KEY-----`

	nanotdfEC256PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM1fJlnzL3bMYoh6yU9aOmbwaWHWq
7CATl+sjaEefNduwTwZZRquNkI5gZzeUuodvGAolQIGhLUdWq9nnS/qx8g==
-----END PUBLIC KEY-----`

	nanotdfEC256PrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGDTNEZTfx0QJH+Cv
BZqwBbl3l9psQEKpYuktczPJe6OhRANCAAQzV8mWfMvdsxiiHrJT1o6ZvBpYdars
IBOX6yNoR58127BPBllGq42QjmBnN5S6h28YCiVAgaEtR1ar2edL+rHy
-----END PRIVATE KEY-----`

	nanotdfEC384PublicKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDIVAsQDhX/eyPwouPbsxReSWrs0vlgdD
s3kp0xhuYNIsEn6geCTHzun15DrmW93/vMdUGwdhuZHDEgNCMM5K3Tkp12husDyc
9wSoe9aBJItnbFPYXV83qu4AndpZh09l
-----END PUBLIC KEY-----`

	nanotdfEC384PrivateKey = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDxrtzz4hqeu7NVjW8b
z/VV6cGBHWbMK18YC7Z9Z3p53zJ8uNaWzld3uCoy3DVHc6GhZANiAAQMhUCxAOFf
97I/Ci49uzFF5JauzS+WB0OzeSnTGG5g0iwSfqB4JMfO6fXkOuZb3f+8x1QbB2G5
kcMSA0IwzkrdOSnXaG6wPJz3BKh71oEki2dsU9hdXzeq7gCd2lmHT2U=
-----END PRIVATE KEY-----`

	nanotdfEC521publicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBKSdtLB/5LTSsQLqEB2ytZ/lIj0vS
IS2IIgjRvGPUr5F6ZoZ4v78oAMT+rg8INZfC0Mxw429k2AuNXI56WD/jIxABLiB0
Oq7JS/8bGTEEMLptt5CwLzbp7oGXN08SMNMKGuP5fnsD8t89zx7u4AGbF3Btb5iT
O9LiKgComz+oA+dOoU8=
-----END PUBLIC KEY-----`

	nanotdfEC521PrivateKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBfYRA/C4czvXEvqW5
Cwibov7dRy5oFmqpUSxtXKfPpvLZIdldOyeX5EnqY30au8rnknHi50HvZykOCobP
aU0SKhWhgYkDgYYABAEpJ20sH/ktNKxAuoQHbK1n+UiPS9IhLYgiCNG8Y9SvkXpm
hni/vygAxP6uDwg1l8LQzHDjb2TYC41cjnpYP+MjEAEuIHQ6rslL/xsZMQQwum23
kLAvNunugZc3TxIw0woa4/l+ewPy3z3PHu7gAZsXcG1vmJM70uIqAKibP6gD506h
Tw==
-----END PRIVATE KEY-----`

	clientEC256PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPebiI6IF413z3FwiPRpytpTqgDfF
RPqR3T4Y9UHNmiK++aTHtVVIqm/QShe/RX/i9tTp/ugDiMKVhlsnWvp7iQ==
-----END PUBLIC KEY-----`

	clientEC256PrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgswA9Oa+q7mmhgAGF
hdTHWOYKeA8tyFbc75QzeacoQ1ahRANCAAQ95uIjogXjXfPcXCI9GnK2lOqAN8VE
+pHdPhj1Qc2aIr75pMe1VUiqb9BKF79Ff+L21On+6AOIwpWGWyda+nuJ
-----END PRIVATE KEY-----`

	clientEC384PublicKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEN7TqOJkT4HVkEfdXboquj5Setj/NRZ+m
syXDsW03OracrQgC7YcCZGaYOdw7CKyB2mQhUxnUjt24uwzKxrwqdwdVbdCgRZ+q
Qvvv1gTSFPaaynTKcmRKeJrB8E+x402h
-----END PUBLIC KEY-----`

	clientEC384PrivateKey = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC/yMfCqwqHEPHCQ1XT
zbhkdVTnKA5AZENWYw589z1SjJxiEaSf4nvoDe2WdeqDOeyhZANiAAQ3tOo4mRPg
dWQR91duiq6PlJ62P81Fn6azJcOxbTc6tpytCALthwJkZpg53DsIrIHaZCFTGdSO
3bi7DMrGvCp3B1Vt0KBFn6pC++/WBNIU9prKdMpyZEp4msHwT7HjTaE=
-----END PRIVATE KEY-----`

	clientEC521PublicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBbCtibYZHdlg4ZRa2RAIdNrEQe1K+
/g6s6mwAduMulwDRjh2HyXmqMITIi8pLdBuxqemyIp3iA0bBQO9+q8vuv7sAj7L4
E9taFLDINdJN9QbNXkfiIqPEgbrFmZSg6jjU5h7qkMd63kt4he2LuBheduWx1Pcy
3bZlcIP9SNOY614VF7A=
-----END PUBLIC KEY-----`

	clientEC521PrivateKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBAif12Nlxa+RgSdYB
pn170EbEeXE8ORFYtSofBKEuCKd3FgxHCU6UPUENXX3oligX9tB7xq1hZVSS1Bk3
W9aAZDqhgYkDgYYABAFsK2Jthkd2WDhlFrZEAh02sRB7Ur7+DqzqbAB24y6XANGO
HYfJeaowhMiLykt0G7Gp6bIineIDRsFA736ry+6/uwCPsvgT21oUsMg10k31Bs1e
R+Iio8SBusWZlKDqONTmHuqQx3reS3iF7Yu4GF525bHU9zLdtmVwg/1I05jrXhUX
sA==
-----END PRIVATE KEY-----`
)

const (
	// this wrapped key is generated by encrypting 32 byte symmetric key with  kasRSA2048PublicKey
	rsa2048WrappedKey   = `rKNvfoTo8vl+cfFuaWFxu+7btyj0DrMR59iIpgugyKjnb0V+dlaVFIw03UbWThEZA/1xGYYTK4CsX3J5h4FV0kAAdMXkRjaW7fygigHPixailHjDRuA34CpL6ndq+mIa6fWZ1hRbpXu3fOOfnBT+33wGhNH7sowNtNKJvNLzlta1ZObPZCPfdNuJ0wZz4eAkKijN7Lvtqt4Ts6Jtb9DOZ0GTBZBHx8j9JH3avE3Tkj0KSUydpSQRgojCkgdWDVOK6L3YcETTObMKUKPwzljBZAEUCnxi1nNGGmpytF1WfIyrUTQPJ1fPKlkCWZV7NnJ+Mk0U760hQBHg669vhw1+Cg==`
	rsa2048ActualSymKey = `ac0be299f7e067d63c524f1a56e38c6a9657f3e20983b42e3f6116a3a08fe7cc`

	// this wrapped key is generated by encrypting 32 byte symmetric key with  kasRSA3072PublicKey
	rsa3072WrappedKey   = `vk6h3gomD6P9aOA0sJ4Hiq3qSARbfKeZhIumVA9QTA1dYdUyMWm41GpCbU6goOiJOQ181zdgQah27BzztMrxDn68SkCJ1PggMWcALdqEEtDtlgWGmSPdYCMgsdXOfGfp63nSHT+Sk/AKi3pNlwpcJdCILRlKd2sD5WrhvFGvz2OJFKb50aYMmwG8+ZSPdwjHGm1/+mPG41UfEgLEWfdYvK7annnTlgR5fM/ke71OsAj9Su3g9XiAltQ7qXHJXeAMLiw9xjgcRRb+5WzX3waJhFsNF4kBFkEoOkAUoFKFhj0N9FJFAs77fPzYmUyVNKEyAQJOuLVkTMemK1IPAzHNbuWdRS6iEh6qvGTjSa3eHJNvHcdW8FMEX/T1M6eVG/kZjWXknFeuLZ37uEWB6jy5IAUNHiwoPv+6USDt43ALT9wyEhAGORN3Va4WBRzyDaXButB9mzprJ6Iy1RKOUWTtpCYhb1HIjGBdVJhNu21IXLMDVce5/FdRmL46sRY1p3d/`
	rsa3072ActualSymKey = `9220975a6eb4a6014b01d904a483a08dfcbd0ed87d6c2d827522b7f4728ee0ef`

	// this wrapped key is generated by encrypting 32 byte symmetric key with  kasRSA4096PublicKey
	rsa4096WrappedKey   = `j+myfvdo5zIv0qYOdn4ZCrGrWq/EHnFua2ifklGkhPd6mGh0TkFD3lcTB6ZnDq+a9Rcq1ugt6KBK8wImgTowZNyM+8V3W7DsGclxgEQZUAh96jZWSiY130L6e2ey1y5SdgvVbUknKkO4Fs7ZySe7ks99F4RFlMXxE1oKG8bvw57ohDF0L1KmSqA0JeMojElyPuqzCkMog1cqCU0RSsUJz6FPfyhgCZsRxZjmOA87mfTNcfIXhk7phAtQaH0aFvhdeS86sORcr19f16Sz9MRMY3ARLnNwENTYYsSqG2JWzoXhtJ7QPBu5adObkQZIg74myAMHOYIQu2KcGGAylivBxo/hRF2+DAFI7bJUN/UezDVspILF5GupUSHa7CCUZPc43AfSO9B+Jw5DlGapnqfE1BtgZrEMxn1p0lpTrRfuaZXWX2sKpO3caHhLBpt83ZdGcz/m01S1bLqMbb1y7cw+6PdZus4ag2jBq1KD2jiyhqhjSrz7mDRTuXh0WDzG1g1a9+vgdJ5u/wt8tGhkugxy+ElCdoHzgbBlf5AUkJ1Yy8coZlp/UvpGaKh+dvhu1MnSxlySp55xG8S/gB/bxU/vnYsacK8HLQAkz1P7Q/mFocPXVNCgSwmXRAaJGQZJehvlyR9ULnIKFpARIidwrFlbzY2qYW/JPCyAtLvbupR2xio=`
	rsa4096ActualSymKey = `413e390d063a87e54c713f03a843c1c190681c86de6e00f0d6ea53f7f9c4a783`
)

func BenchmarkRCAKasRewrap(b *testing.B) {
	benchmarks := []struct {
		name         string
		privateKey   string
		wrappedKey   string
		actualSymKey string
		publicKey    string
	}{
		{
			name:         "RCA2024",
			privateKey:   kasRSA2048PrivateKey,
			wrappedKey:   rsa2048WrappedKey,
			actualSymKey: rsa2048ActualSymKey,
			publicKey:    clientRSA2048PublicKey,
		},
		{
			name:         "RCA3072",
			privateKey:   kasRSA3072PrivateKey,
			wrappedKey:   rsa3072WrappedKey,
			actualSymKey: rsa3072ActualSymKey,
			publicKey:    clientRSA3072PublicKey,
		},
		{
			name:         "RCA4096",
			privateKey:   kasRSA4096PrivateKey,
			wrappedKey:   rsa4096WrappedKey,
			actualSymKey: rsa4096ActualSymKey,
			publicKey:    clientRSA4096PublicKey,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			var symkey []byte
			asymDecryptor, err := NewAsymDecryption(bm.privateKey)
			if err != nil {
				b.Fatalf("NewAsymDecryption failed: %v", err)
			}

			decode, err := Base64Decode([]byte(bm.wrappedKey))
			if err != nil {
				b.Fatalf("Base64Decode failed: %v", err)
			}

			symkey, err = asymDecryptor.Decrypt(decode)
			if err != nil {
				b.Fatalf("Decrypt failed: %v", err)
			}

			asymEncryptor, err := NewAsymEncryption(bm.publicKey)
			if err != nil {
				b.Fatalf("NewAsymEncryption failed: %v", err)
			}

			wrappedKey, err := asymEncryptor.Encrypt(symkey)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}

			_ = Base64Encode(wrappedKey)

			if bm.actualSymKey != hex.EncodeToString(symkey) {
				b.Errorf("Symmetric key mismatch: expected %s, got %s", bm.actualSymKey, hex.EncodeToString(symkey))
			}
		})
	}
}

func BenchmarkEC256KasRewrap(b *testing.B) {
	benchmarks := []struct {
		name             string
		kasPrivateKey    string
		nanotdfPublicKey string
		clientPublicKey  string
		eccMode          ECCMode
	}{
		{"EC256", kasEC256PrivateKey, nanotdfEC256PublicKey, clientEC256PublicKey, ECCModeSecp256r1},
		{"EC384", kasEC384PrivateKey, nanotdfEC384PublicKey, clientEC384PublicKey, ECCModeSecp384r1},
		{"EC521", kasEC521PrivateKey, nanotdfEC521publicKey, clientEC521PublicKey, ECCModeSecp521r1},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// generate symmetric key from Kas private key and ephemeral public key from nano header
			kasECDHKey, err := ComputeECDHKey([]byte(bm.kasPrivateKey), []byte(bm.nanotdfPublicKey))
			require.NoError(b, err, "fail to calculate ecdh key")

			// slat
			digest := sha256.New()
			digest.Write([]byte("L1L"))

			symmetricKey, err := CalculateHKDFWithSize(digest.Sum(nil), kasECDHKey, 32)
			require.NoError(b, err, "fail to calculate HKDF key")

			kasEphemeralECKeyPair, err := NewECKeyPair(bm.eccMode)
			require.NoError(b, err, "fail on NewECKeyPair")

			kasEphemeralPrivateKey, err := kasEphemeralECKeyPair.PrivateKeyInPemFormat()
			require.NoError(b, err, "fail to generate ec private key in pem format")

			// generate session key from sdk public and kas ephemeral private key
			sessionECDHKey, err := ComputeECDHKey([]byte(kasEphemeralPrivateKey), []byte(bm.clientPublicKey))
			require.NoError(b, err, "fail to calculate ecdh key")

			sessionKey, err := CalculateHKDFWithSize(digest.Sum(nil), sessionECDHKey, 32)
			require.NoError(b, err, "fail to calculate HKDF key")

			gcm, err := NewAESGcm(sessionKey)
			require.NoError(b, err, "fail to create aes gcm")

			_, err = gcm.Encrypt(symmetricKey)
			require.NoError(b, err, "fail to encrypt symmetric key")
		})
	}
}

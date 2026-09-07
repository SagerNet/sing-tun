#include "textflag.h"

// func checksumNEON(b []byte, initial uint16) uint16
TEXT ·checksumNEON(SB), NOSPLIT|NOFRAME, $0-34
	MOVD   b_base+0(FP), R0
	MOVD   b_len+8(FP), R1
	MOVHU  initial+24(FP), R2
	REV16W R2, R2
	TBZ    $0, R1, neonEvenLength
	SUB    $1, R1
	MOVBU  (R0)(R1), R3
	ADD    R3, R2

neonEvenLength:
	CMP  $128, R1
	BGE  neonChunk
	CMP  $64, R1
	BLT  neonTail32
	LDP  (R0), (R4, R5)
	LDP  16(R0), (R6, R7)
	LDP  32(R0), (R8, R9)
	LDP  48(R0), (R10, R11)
	ADDS R4, R2
	ADCS R5, R2
	ADCS R6, R2
	ADCS R7, R2
	ADCS R8, R2
	ADCS R9, R2
	ADCS R10, R2
	ADCS R11, R2
	ADC  $0, R2
	ADD  $64, R0
	SUB  $64, R1
	B    neonTail32

neonChunk:
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V1.B16, V1.B16, V1.B16
	VEOR V2.B16, V2.B16, V2.B16
	VEOR V3.B16, V3.B16, V3.B16
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	VEOR V7.B16, V7.B16, V7.B16

	AND  $-64, R1, R3
	MOVD $1048576, R4
	CMP  R4, R3
	CSEL LT, R3, R4, R3
	SUB  R3, R1
	ADD  R3, R0, R5

neonInner:
	VLD1.P  64(R0), [V16.B16, V17.B16, V18.B16, V19.B16]
	VUADDW  V16.H4, V0.S4, V0.S4
	VUADDW2 V16.H8, V1.S4, V1.S4
	VUADDW  V17.H4, V2.S4, V2.S4
	VUADDW2 V17.H8, V3.S4, V3.S4
	VUADDW  V18.H4, V4.S4, V4.S4
	VUADDW2 V18.H8, V5.S4, V5.S4
	VUADDW  V19.H4, V6.S4, V6.S4
	VUADDW2 V19.H8, V7.S4, V7.S4
	CMP     R5, R0
	BNE     neonInner

	VADD    V1.S4, V0.S4, V0.S4
	VADD    V3.S4, V2.S4, V2.S4
	VADD    V5.S4, V4.S4, V4.S4
	VADD    V7.S4, V6.S4, V6.S4
	VADD    V2.S4, V0.S4, V0.S4
	VADD    V6.S4, V4.S4, V4.S4
	VUADDLV V0.S4, V16
	VUADDLV V4.S4, V17
	VMOV    V16.D[0], R6
	VMOV    V17.D[0], R7
	ADDS    R6, R2
	ADCS    R7, R2
	ADC     $0, R2

	CMP $64, R1
	BGE neonChunk

neonTail32:
	TBZ  $5, R1, neonTail16
	LDP  (R0), (R4, R5)
	LDP  16(R0), (R6, R7)
	ADDS R4, R2
	ADCS R5, R2
	ADCS R6, R2
	ADCS R7, R2
	ADC  $0, R2
	ADD  $32, R0

neonTail16:
	TBZ  $4, R1, neonTail8
	LDP  (R0), (R4, R5)
	ADDS R4, R2
	ADCS R5, R2
	ADC  $0, R2
	ADD  $16, R0

neonTail8:
	TBZ  $3, R1, neonTail4
	MOVD (R0), R4
	ADDS R4, R2
	ADC  $0, R2
	ADD  $8, R0

neonTail4:
	TBZ   $2, R1, neonTail2
	MOVWU (R0), R4
	ADDS  R4, R2
	ADC   $0, R2
	ADD   $4, R0

neonTail2:
	TBZ   $1, R1, neonFold
	MOVHU (R0), R4
	ADDS  R4, R2
	ADC   $0, R2

neonFold:
	AND    $0xffffffff, R2, R3
	ADD    R2>>32, R3, R2
	AND    $0xffff, R2, R3
	ADD    R2>>16, R3, R2
	AND    $0xffff, R2, R3
	ADD    R2>>16, R3, R2
	AND    $0xffff, R2, R3
	ADD    R2>>16, R3, R2
	REV16W R2, R2
	MOVH   R2, ret+32(FP)
	RET

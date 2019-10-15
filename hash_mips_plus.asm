.text
main:
#intialize B
lui 	$8 , 0xFA19
ori 	$8, $8, 0xE366	#B = 0xFA19E366
ori 	$9, $0, 0x1		#A = 1
ori	$11, $0, 0x2020	#data address
ori	$12, $0, 0x0		#pattern_count = 0

LOOP:
ori	$16, $0, 0x0		#index = 1
or	$17, $0, $9
LOOP1:
multu 	$17, $8		#[hi, lo] = A * B
mfhi 	$17 
mflo 	$18
xor	$17, $17, $18		#A = hi xor lo
addi	$16, $16, 0x1		#index ++
slti	$19, $16, 0x5		#if index < 5
bne	$19, $0, LOOP1	#loop

fold	$17
sb	$17, 0($11)

ori	$13, $0, 0x1F	#mask = b0001 1111
ori	$14, $0, 0x0		#mask_index = 0
ori	$18, $0, 0x0		#flag = false
MASKLOOP:
and	$15, $17, $13		#HASH and mask
bne	$15, $13, LABEL1
ori	$18, $0, 0x1		#flag = true
LABEL1:
addi	$14, $14, 0x1		#mask_index ++
sll	$13, $13, 0x1		#mask << 1
slti	$19, $14, 0x4		#if mask_index < 4
bne	$19, $0, MASKLOOP	#loop

beq	$18, $0, LABEL2
addi	$12, $12, 0x1
LABEL2:

addi	$9, $9, 0x1		#A ++
addi	$11, $11, 0x1		#data address ++
slti	$10, $9, 0x65		#if A < 100
bne	$10, $0, LOOP	#loop

ori 	$11, $0, 0x2008
sb	$12, 0($11)
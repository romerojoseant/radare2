OBJ_MSP430=anal_msp430.o

STATIC_OBJ+=${OBJ_MSP430}
OBJ_MSP430+=../arch/msp430/msp430_disas.o
TARGET_MSP430=anal_msp430.${EXT_SO}

ALL_TARGETS+=${TARGET_MSP430}

${TARGET_MSP430}: ${OBJ_MSP430} ${SHARED_OBJ}
	${CC} $(call libname,anal_msp430) ${CFLAGS} \
		-o ${TARGET_MSP430} ${OBJ_MSP430}

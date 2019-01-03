#include "ipv4.h"
#include "netinet/in.h"
#include "utils.h"

uint16_t checksum(register uint16_t *ptr, register uint32_t len, register uint32_t sum)
{
	// Credit: 	http://www.csee.usf.edu/~kchriste/tools/checksum.c
	//			https://github.com/chobits/tapip
	uint16_t			odd_byte;

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (len > 1)  {
		sum += *ptr++;
		len -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (len == 1) {
		odd_byte = 0;		/* make sure top half is zero */
		*((uint8_t *) &odd_byte) = *(uint8_t *)ptr;   /* one byte only */
		sum += odd_byte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	return (uint16_t)~sum;;
}
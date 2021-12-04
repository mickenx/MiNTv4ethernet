/*
 *	v4net , ethernet driver for Vampire V4
 *  Based on FreeMiNT dummy ethernet driver
 *	12/14/94, Kay Roemer. 11/09/2021 Michael Grunditz
 */
#include <malloc.h>
#include <time.h>
# include "global.h"

# include "buf.h"
# include "inet4/if.h"
# include "inet4/ifeth.h"
# include "netinfo.h"
#include "debug.h"
#include "svethlana/svethlana_i6.h"
# include "mint/sockio.h"
# include <mint/osbind.h>
# include <mint/ssystem.h>
# include "arch/tosbind.h"
typedef u_int32_t               uint32_t;

        typedef u_int32_t               uint32;

        typedef u_int16_t               uint16_t;

        typedef u_int16_t               uint16;

        typedef int32_t                 int32;

        typedef int16_t                 int16;
	typedef u_int8_t                 uint8_t;


#define MEMSIZE 204800
/*
 * Our interface structure
 */
static struct netif if_v4net;

static volatile uint32_t alignmem;
static volatile uint32_t swposcopy;
static void * mem4;
static uint8_t hwtmp[6];
static int framecount;
//static struct timeval tval_before, tval_after, tval_result;



typedef struct _v4_ethernet_t
{
#if 1
  uint16_t dma;
  uint8_t  mac[6];
 #else
  uint32_t mac1;         /* DMA_ON<<31 | MAC(0:15)                   */
  uint32_t mac2;         /* MAC(16:47)                               */
#endif
  uint32_t multicast1;   /* high order bits multicast hash           */
  uint32_t multicast2;   /* low  order bits multicast hash           */
  uint32_t rx_start;     /* DMA buffer start (aligned to 2048 bytes) */
  uint32_t rx_stop;      /* DMA buffer end (aligned to 2048 bytes)   */
  uint32_t rx_swpos;     /* RX software position (barrier)           */
  uint32_t rx_hwpos;     /* hardware RX write position               */
  uint32_t txword;       /* write port for TX FIFO (32 Bits)         */
  uint32_t txqueuelen;   /* number of words in TX FIFO               */
} v4_ethernet_t;

volatile v4_ethernet_t * v4e = (v4_ethernet_t*)0xde0020;
/*
 * Prototypes for our service functions
 */
static long	v4net_open	(struct netif *);
static long	v4net_close	(struct netif *);
static long	v4net_output	(struct netif *, BUF *, const char *, short, short);
static long	v4net_ioctl	(struct netif *, short, long);
static long	v4net_config	(struct netif *, struct ifopt *);
void _cdecl v4net_recv(void);
static void v4net_install_int (void);
uint8_t* hwd_mac = (uint8_t*)0xde0020;
/*
 * This gets called when someone makes an 'ifconfig up' on this interface
 * and the interface was down before.
   V4net : online in init will change
 */
static long
v4net_open (struct netif *nif)
{



volatile uint32_t *mac1ptr=(uint32_t*)0xde0020;

*mac1ptr = (1L<<31 |0x80<<8|0x06);

static	char message [100];
ksprintf (message, "addr: 0x%lx\n\r", alignmem);
c_conws(message);
#if 0
__asm__ __volatile__
(
	"move.w #0xa000,0xdff29a\n\t"
);
#endif
framecount=0;
	return 0;
}

static void
v4net_install_int (void)
{


	old_i6_int = Setexc (0x6c>>2, (long) interrupt_i6);


}

void _cdecl v4net_recv(void)
{

short type;
volatile uint32_t * hw_write = (ulong*) 0xde003c;
volatile uint32_t * sw_write = (ulong*) 0xde0038;
uint32_t clktmp,clktmp2;

uint32_t lenlong=0;
static	char message [100];
short frame_len = 0;
uint32_t tmp=0;
uint32_t tmp2=0;
uint32_t tmp3=0;
uint32_t	*dest;
uint8_t * chkaddr;

volatile uint32_t * c200hz = (uint32_t*)0x4ba;
struct netif * nif=&if_v4net;
BUF * b;

uint32_t elapsed=0;


if (*hw_write > 0xfff00000)
{
	//c_conws("offline \n\r");
	return;
}
rxrestart:
if ((uint32_t)*(hw_write)==(uint32_t)swposcopy)
{
//c_conws("no buf recv\n\r");


	return;
}


tmp=swposcopy;
tmp2=(uint32_t)2048+(swposcopy); //(swposcopy+2048);
ksprintf (message, "swposcopy:1 0x%lx\n\r", *(uint32_t*)swposcopy);
//c_conws(message);
clktmp=*c200hz;

if (tmp2>=(uint32_t)(alignmem+MEMSIZE)) {
	ksprintf (message, "swposcopy wrap : 0x%x\n\r", swposcopy);
//c_conws(message);

	tmp2=alignmem;
	}
	swposcopy=tmp2;
chkaddr=(uint8_t*)tmp2+8;
#if 0
// NEEDED FOR DHCP
if ((uint8_t)chkaddr[5]!=hwtmp[5])
	{

		//ksprintf (message, "hwcheck:idx %d dest 0x%x me 0x%x\n\r",i,(chkaddr[i]),hwtmp[i] );
	//	c_conws(message);
		//goto rxrestart;
		if (tmp!=alignmem)
			*sw_write=tmp;
			return;
	}
//	}
#endif
frame_len =(short) *((short*)tmp2+3) ;//(uint16_t)bytecopy[6];(char*)(swposcopy+6));

*((short*)tmp2+3)=(short)0;
frame_len = frame_len & 2047;

if (frame_len < 14 || frame_len > 1535)
{
	nif->in_errors++;
	c_conws("SIZE ERROR\r\n");
   goto rxrestart;


	return;

}
b = buf_alloc (frame_len +200, 100, BUF_ATOMIC);
//c_conws("start recv\n\r");
if (!b)
{
//c_conws("BUF ERROR\r\n");
	nif->in_errors++;
__asm__ __volatile__
(
	"move.l #0xa000,0xdff29a\n\t"
);
	return;
}

b->dstart = (char*)(((uint32_t)(b->dstart)) & 0xFFFFFFFCUL);
b->dend = (char*)(((uint32_t)(b->dend)) & 0xFFFFFFFCUL);
dest = (uint32_t*)(b->dstart);


lenlong= ((frame_len+ 3UL)& 0xFFFC) >> 2;



#if 0
			//Frames of a zero size or type are not useful.
			//these also crash AROS.
			if( frametype == 0 )
			{
				c_conws("zero type \r\n");
				//KPrintF( "Skipping Frametype %04x (zero size/type).\n", frametype );
				return;
			}

			//Skip VLAN frames.
			//TODO: Is this really needed?
			if( frametype == 0x8100 )
			{
				c_conws("vlan type\r\n");
				//KPrintF( "Skipping Frametype %04x (VLAN Tagged).\n", frametype );
				return;

			}
#endif
tmp3=tmp2+8;
uint32_t* asmsrc = (uint32_t*)tmp3;


#if 0

while(i<lenlong)
{

	*(dest+i)=*((uint32_t*)tmp2+i+2);
	i++;
	*(dest+i)=*((uint32_t*)tmp2+i+2);
  	i++;
}
#endif
//frame_len= ((frame_len+ 3UL)& 0xFFFC);
#if 1
__asm__ __volatile__
		(
	"move.l %2,%%d1\n\t"
	"move.l %0,%%a0\n\t"
	"move.l %1,%%a1\n\t"
	"3:\n\t"
	"move.l (%%a1)+,(%%a0)+\n\t"
	"move.l (%%a1)+,(%%a0)+\n\t"
	"subq.l	#2,%%d1\n\t"
	"bgt.s	3b\n\t"
	:  /*output*/
	: "g" (dest), "g" (asmsrc), "g" (lenlong)
	: "d0", "d1", "d2", "a0", "a1", "a2"
			);

#endif
//c_conws("after copy\r\n");
b->dend += frame_len -4;
                        //TODO: should we subtract 4 here, to skip the CRC?

                                //(uint32)(frame_len - 4UL);

                //TODO: should we subtract 4 here, to skip the CRC?

                                if((b->dend) < (b->dstart))

                                {

                                        c_conws("RX: dend < dstart!\r\n");

                                }


//c_conws("1 recv\n\r");


if (nif->bpf)
    bpf_input (nif, b);

//c_conws("3 recv\n\r");
				type = eth_remove_hdr(b);

				// and enqueue packet
				if(!if_input(nif, b, 0UL, type))
					nif->in_packets++;
				else
				{
					nif->in_errors++;
	//				c_conws("input packet failed when receiving!\n\r");
				}

if ((uint32_t)*(hw_write)==(uint32_t)swposcopy+2048)
{

	if (tmp!=alignmem)
*sw_write=tmp;


	return;
}

chkaddr=(uint8_t*)swposcopy+2048+8;


if ((uint8_t)chkaddr[5]==hwtmp[5])
{

	clktmp2=*c200hz;

		elapsed+=(uint32_t)clktmp2-clktmp;

	if (elapsed <40)
	goto rxrestart;
	else
	elapsed=0;
}
if (tmp!=alignmem)
*sw_write=tmp;


}
/*
 * Opposite of v4net_open(), is called when 'ifconfig down' on this interface
	 * is done and the interface was up before.
 */
static long
v4net_close (struct netif *nif)
{

	v4e->dma=0;

	return 0;
}

/*
 * This routine is responsible for enqueing a packet for later sending.
 * The packet it passed in `buf', the destination hardware address and
 * length in `hwaddr' and `hwlen' and the type of the packet is passed
 * in `pktype'.
 *
 * `hwaddr' is guaranteed to be of type nif->hwtype and `hwlen' is
 * garuanteed to be equal to nif->hwlocal.len.
 *
 * `pktype' is currently one of (definitions in if.h):
 *	PKTYPE_IP for IP packets,
 *	PKTYPE_ARP for ARP packets,
 *	PKTYPE_RARP for reverse ARP packets.
 *
 * These constants are equal to the ethernet protocol types, ie. an
 * Ethernet driver may use them directly without prior conversion to
 * write them into the `proto' field of the ethernet header.
 *
 * If the hardware is currently busy, then you can use the interface
 * output queue (nif->snd) to store the packet for later transmission:
 *	if_enqueue (&nif->snd, buf, buf->info).
 *
 * `buf->info' specifies the packet's delivering priority. if_enqueue()
 * uses it to do some priority queuing on the packets, ie. if you enqueue
 * a high priority packet it may jump over some lower priority packets
 * that were already in the queue (ie that is *no* FIFO queue).
 *
 * You can dequeue a packet later by doing:
 *	buf = if_dequeue (&nif->snd);
 *
 * This will return NULL is no more packets are left in the queue.
 *
 * The buffer handling uses the structure BUF that is defined in buf.h.
 * Basically a BUF looks like this:
 *
 * typedef struct {
 *	long buflen;
 *	char *dstart;
 *	char *dend;
 *	...
 *	char data[0];
 * } BUF;
 *
 * The structure consists of BUF.buflen bytes. Up until BUF.data there are
 * some header fields as shown above. Beginning at BUF.data there are
 * BUF.buflen - sizeof (BUF) bytes (called userspace) used for storing the
 * packet.
 *
 * BUF.dstart must always point to the first byte of the packet contained
 * within the BUF, BUF.dend points to the first byte after the packet.
 *
 * BUF.dstart should be word aligned if you pass the BUF to any MintNet
 * functions! (except for the buf_* functions itself).
 *
 * BUF's are allocated by
 *	nbuf = buf_alloc (space, reserve, mode);
 *
 * where `space' is the size of the userspace of the BUF you need, `reserve'
 * is used to set BUF.dstart = BUF.dend = BUF.data + `reserve' and mode is
 * one of
 *	BUF_NORMAL for calls from kernel space,
 *	BUF_ATOMIC for calls from interrupt handlers.
 *
 * buf_alloc() returns NULL on failure.
 *
 * Usually you need to pre- or postpend some headers to the packet contained
 * in the passed BUF. To make sure there is enough space in the BUF for this
 * use
 *	nbuf = buf_reserve (obuf, reserve, where);
 *
 * where `obuf' is the BUF where you want to reserve some space, `reserve'
 * is the amount of space to reserve and `where' is one of
 *	BUF_RESERVE_START for reserving space before BUF.dstart
 *	BUF_RESERVE_END for reserving space after BUF.dend
 *
 * Note that buf_reserve() returns pointer to a new buffer `nbuf' (possibly
 * != obuf) that is a clone of `obuf' with enough space allocated. `obuf'
 * is no longer existant afterwards.
 *
 * However, if buf_reserve() returns NULL for failure then `obuf' is
 * untouched.
 *
 * buf_reserve() does not modify the BUF.dstart or BUF.dend pointers, it
 * only makes sure you have the space to do so.
 *
 * In the worst case (if the BUF is to small), buf_reserve() allocates a new
 * BUF and copies the old one to the new one (this is when `nbuf' != `obuf').
 *
 * To avoid this you should reserve enough space when calling buf_alloc(), so
 * buf_reserve() does not need to copy. This is what MintNet does with the BUFs
 * passed to the output function, so that copying is never needed. You should
 * do the same for input BUFs, ie allocate the packet as eg.
 *	buf = buf_alloc (nif->mtu+sizeof (eth_hdr)+100, 50, BUF_ATOMIC);
 *
 * Then up to nif->mtu plus the length of the ethernet header bytes long
 * frames may ne received and there are still 50 bytes after and before
 * the packet.
 *
 * If you have sent the contents of the BUF you should free it by calling
 *	buf_deref (`buf', `mode');
 *
 * where `buf' should be freed and `mode' is one of the modes described for
 * buf_alloc().
 *
 * Functions that can be called from interrupt:
 *	buf_alloc (..., ..., BUF_ATOMIC);
 *	buf_deref (..., BUF_ATOMIC);
 *	if_enqueue ();
 *	if_dequeue ();
 *	if_input ();
 *	eth_remove_hdr ();
 *	addroottimeout (..., ..., 1);
 */

static long
v4net_output (struct netif *nif, BUF *buf, const char *hwaddr, short hwlen, short pktype)
{
	BUF *nbuf;
	short type;
	long r;
	uint32_t d0,tlen,rounded_len,stufflen;
//static	char message [100];



 	ulong txfifo = 0xde0040;
 	ulong txq = 0xde0044;
	ulong *txptr = (ulong*)txfifo;
	ulong *txqtr = (ulong*)txq;
	uint32_t i =0;
	uint32_t r2;
	stufflen=0;
	rounded_len=0;

	/*
	 * This is not needed in real hardware drivers. We test
	 * only if the destination hardware address is either our
	 * hw or our broadcast address, because we loop the packets
	 * back only then.
	 */
#if 1
	if (memcmp (hwaddr, nif->hwlocal.adr.bytes, ETH_ALEN) &&
	    memcmp (hwaddr, nif->hwbrcst.adr.bytes, ETH_ALEN))
	{
	//	c_conws ("send out \n");
		/*
		 * Not for me.
		 */
/*		buf_deref (buf, BUF_NORMAL);
		return 0;*/
	}
#endif
	stufflen=0;

	/*
	 * Attach eth header. MintNet provides you with the eth_build_hdr
	 * function that attaches an ethernet header to the packet in
	 * buf. It takes the BUF (buf), the interface (nif), the hardware
	 * address (hwaddr) and the packet type (pktype).
	 *
	 * Returns NULL if the header could not be attached (the passed
	 * buf is thrown away in this case).
	 *
	 * Otherwise a pointer to a new BUF with the packet and attached
	 * header is returned and the old buf pointer is no longer valid.
	 */
	nbuf = eth_build_hdr (buf, nif, hwaddr, pktype);
	if (nbuf == 0)
	{
		c_conws ("send nonbuf \n");
		nif->out_errors++;
		return ENOMEM;
	}


nif->out_packets++;


	/*
	 * Here you should either send the packet to the hardware or
	 * enqueue the packet and send the next packet as soon as
	 * the hardware is finished.
	 *
	 * If you are done sending the packet free it with buf_deref().
	 *
	 * Before sending it pass it to the packet filter.
	 */

		if (nif->bpf) {
           bpf_input (nif, nbuf);
       //    c_conws("bpf\n\r");
           }
        tlen = (nbuf->dend) - (nbuf->dstart);
        rounded_len = (tlen + 3UL) & 0xFFFC ;
        r2=rounded_len>>2;
		#if 1
d0=r2;
	if(*txqtr)
	{
		volatile uint32_t d2 = 0;
		volatile uint32_t d1 = ((0xfffffffdUL - d0)) + 512;
		for(d2 = 800000UL; d2 > 0; d2--)
		{
		for (i=0;i<50;i++)
		{
			asm("nop;");
			asm("nop;");
			asm("nop;");
			asm("nop;");
			asm("nop;");
		}
			//ksprintf (message, "tx q : %lx\n\r", *txqtr);
	        //c_conws(message);
			if(*txqtr <= d1)
				goto freebuffer;
		}
		//c_conws("tx full\n\r");
		return -1;
	}
	else
	{
		goto freebuffer;
	}
#endif
freebuffer:


        //If the packet is greater than 1536 we return error
//ksprintf (message, "tx len : 0x%lx\n\r",tlen);
//	 c_conws(message);
        if (rounded_len > 1536UL)
		return (1);
	if (rounded_len<64) {
		//c_conws("rounded len err\n\r");
		stufflen=64-rounded_len;
		}
		//stufflen=0;
	if (stufflen>0) {
	//ksprintf (message, "stuff len : %d\n\r",stufflen);
	 //c_conws(message);

	*txptr=64;
	}
	else
	{
		//c_conws("set round\n\r");
		stufflen=0UL;
	*txptr=rounded_len;
	}

	i=0;
	uint32_t * dest = (uint32_t*)nbuf->dstart;
#if 1
if (rounded_len)
{
	for (i=0;i<(rounded_len>>2);i++)
	{
		*((uint32_t*)txptr)=*(dest+i);

		//*((uint32_t*)txptr)=*(dest++);
		//i++;
	}
}
#endif
#if 0
if (rounded_len)
{
	__asm__ __volatile__
		(
	"move.l %1,%%d1\n\t"
	"move.l %0,%%a0\n\t"
	"1:\n\t"
	"move.l (%%a0)+,%%d2\n\t"
	"move.l %%d2,0xde0040\n\t"
	"subq.l	#4,%%d1\n\t"
	"bgt.s	1b\n\t"
	:  /*output*/
	: "g" (dest), "g" (rounded_len)
	: "d0", "d1", "d2", "a0", "a1", "a2"
			);
}
#endif

#if 0
	if (stufflen)
{
	__asm__ __volatile__
		(
	"move.l %0,%%d1\n\t"
	"2:\n\t"
	"move.l #0,0xde0040\n\t"
	"subq.l	#4,%%d1\n\t"
	"bgt.s	2b\n\t"
	:  /*output*/
	: "g" (stufflen)
	: "d0", "d1", "d2", "a0", "a1", "a2"
			);
}
#endif
#if 1
	if (stufflen)
{

	//c_conws("stufflen!!\n\r");
	//stufflen>>2;
	for(i=0;i<(stufflen>>2);i++)
	{
		__asm__ __volatile__
		(
	"move.l #0,0xde0040\n\t"

			);
		//*((uint32_t*)txptr)=0;//(uint32_t)zerostuff;
	}
	}


#endif

	//c_conws ("send return\n");
	buf_deref (nbuf, BUF_NORMAL);
	return (0);
	/*
	 * Now follows the input side code of the driver. This is
	 * only part of the output function, because this example
	 * is a loopback driver.
	 */

	/*
	 * Before passing it to if_input pass it to the packet filter.
	 * (but before stripping the ethernet header).
	 *
	 * For the loopback driver this doesn't make sense... We
	 * would see all packets twice!
	 *
	 * if (nif->bpf)
	 *	bpf_input (nif, buf);
	 */

	/*
	 * Strip eth header and get packet type. MintNet provides you
	 * with the function eth_remove_hdr(buf) for this purpose where
	 * `buf' contains an ethernet frame. eth_remove_hdr strips the
	 * ethernet header and returns the packet type.
	 */
	type = eth_remove_hdr (nbuf);

	/*
	 * Then you should pass the buf to MintNet for further processing,
	 * using
	 *	if_input (nif, buf, 0, type);
	 *
	 * where `nif' is the interface the packet was received on, `buf'
	 * contains the packet and `type' is the packet type, which must
	 * be a valid ethernet protcol identifier.
	 *
	 * if_input takes `buf' over, so after calling if_input() on it
	 * you can no longer access it.
	 */
	r = if_input (nif, nbuf, 0, type);
	if (r)
		nif->in_errors++;
	else
		nif->in_packets++;

	return r;
}

/*
 * MintNet notifies you of some noteable IOCLT's. Usually you don't
 * need to act on them because MintNet already has done so and only
 * tells you that an ioctl happened.
 *
 * One useful thing might be SIOCGLNKFLAGS and SIOCSLNKFLAGS for setting
 * and getting flags specific to your driver. For an example how to use
 * them look at slip.c
 */
static long
v4net_ioctl (struct netif *nif, short cmd, long arg)
{
	struct ifreq *ifr;

	switch (cmd)
	{
		case SIOCSIFNETMASK:
		case SIOCSIFFLAGS:
		case SIOCSIFADDR:
			return 0;

		case SIOCSIFMTU:
			/*
			 * Limit MTU to 1500 bytes. MintNet has alraedy set nif->mtu
			 * to the new value, we only limit it here.
			 */
			if (nif->mtu > ETH_MAX_DLEN)
				nif->mtu = ETH_MAX_DLEN;
			return 0;

		case SIOCSIFOPT:
			/*
			 * Interface configuration, handled by v4net_config()
			 */
			ifr = (struct ifreq *) arg;
			return v4net_config (nif, ifr->ifru.data);
	}

	return ENOSYS;
}

/*
 * Interface configuration via SIOCSIFOPT. The ioctl is passed a
 * struct ifreq *ifr. ifr->ifru.data points to a struct ifopt, which
 * we get as the second argument here.
 *
 * If the user MUST configure some parameters before the interface
 * can run make sure that v4net_open() fails unless all the necessary
 * parameters are set.
 *
 * Return values	meaning
 * ENOSYS		option not supported
 * ENOENT		invalid option value
 * 0			Ok
 */
static long
v4net_config (struct netif *nif, struct ifopt *ifo)
{
# define STRNCMP(s)	(strncmp ((s), ifo->option, sizeof (ifo->option)))

	if (!STRNCMP ("hwaddr"))
	{
		uchar *cp;
		/*
		 * Set hardware address
		 */
		if (ifo->valtype != IFO_HWADDR)
			return ENOENT;
		memcpy (nif->hwlocal.adr.bytes, ifo->ifou.v_string, ETH_ALEN);
		cp = nif->hwlocal.adr.bytes;
		UNUSED (cp);
		DEBUG (("v4net: hwaddr is %x:%x:%x:%x:%x:%x",
			cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]));
	}
	else if (!STRNCMP ("braddr"))
	{
		uchar *cp;
		/*
		 * Set broadcast address
		 */
		if (ifo->valtype != IFO_HWADDR)
			return ENOENT;
		memcpy (nif->hwbrcst.adr.bytes, ifo->ifou.v_string, ETH_ALEN);
		cp = nif->hwbrcst.adr.bytes;
		UNUSED (cp);
		DEBUG (("v4net: braddr is %x:%x:%x:%x:%x:%x",
			cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]));
	}
	else if (!STRNCMP ("debug"))
	{
		/*
		 * turn debuggin on/off
		 */
		if (ifo->valtype != IFO_INT)
			return ENOENT;
		DEBUG (("v4net: debug level is %ld", ifo->ifou.v_long));
	}
	else if (!STRNCMP ("log"))
	{
		/*
		 * set log file
		 */
		if (ifo->valtype != IFO_STRING)
			return ENOENT;
		DEBUG (("v4net: log file is %s", ifo->ifou.v_string));
	}

	return ENOSYS;
}

/*
 * Initialization. This is called when the driver is loaded. If you
 * link the driver with main.o and init.o then this must be called
 * driver_init() because main() calles a function with this name.
 *
 * You should probe for your hardware here, setup the interface
 * structure and register your interface.
 *
 * This function should return 0 on success and != 0 if initialization
 * fails.
 */
long driver_init(void);
long
driver_init (void)
{
	//unsigned char hwtmp[6];

	static char message[100];
	static char my_file_name[128];


volatile uint32_t *mac1ptr = (uint32_t*)0xde0020;

volatile uint32_t* mac2ptr =(uint32_t*) 0xde0024;

//volatile ulong * multi1ptr = (ulong *)0xde0028;

//volatile ulong * multi2ptr = (ulong*)0xde002c;

volatile ulong * swposptr = (ulong *)0xde0038;









	/*
	 * Set interface name
	 */
	strcpy (if_v4net.name, "en");
	/*
	 * Set interface unit. if_getfreeunit("name") returns a yet
	 * unused unit number for the interface type "name".
	 */
	if_v4net.unit = if_getfreeunit ("en");
	/*
	 * Alays set to zero
	 */
	if_v4net.metric = 0;
	/*
	 * Initial interface flags, should be IFF_BROADCAST for
	 * Ethernet.
	 */
	if_v4net.flags = IFF_BROADCAST;
	/*
	 * Maximum transmission unit, should be >= 46 and <= 1500 for
	 * Ethernet
	 */
	if_v4net.mtu = 1500;
	/*
	 * Time in ms between calls to (*if_v4net.timeout) ();
	 */
	if_v4net.timer = 0;

	/*
	 * Interface hardware type
	 */
	if_v4net.hwtype = HWTYPE_ETH;
	/*
	 * Hardware address length, 6 bytes for Ethernet
	 */
	if_v4net.hwlocal.len =
	if_v4net.hwbrcst.len = ETH_ALEN;

	/*
	 * Set interface hardware and broadcast addresses. For real ethernet
	 * drivers you must get them from the hardware of course!
	 */
	hwtmp[0]=0x06;
	hwtmp[1]=0x80;
	hwtmp[2]=0x11;
	hwtmp[3]=0x04;
	hwtmp[4]=0x04;
	hwtmp[5]=0x04;

	memcpy (if_v4net.hwlocal.adr.bytes, hwtmp, ETH_ALEN);
	//memcpy (if_v4net.hwbrcst.adr.bytes, hwbtmp, ETH_ALEN);
	memcpy (if_v4net.hwbrcst.adr.bytes, "\377\377\377\377\377\377", ETH_ALEN);

	/*
	 * Set length of send and receive queue. IF_MAXQ is a good value.
	 */
	if_v4net.rcv.maxqlen = IF_MAXQ;
	if_v4net.snd.maxqlen = IF_MAXQ;
	/*
	 * Setup pointers to service functions
	 */
	if_v4net.open = v4net_open;
	if_v4net.close = v4net_close;
	if_v4net.output = v4net_output;
	if_v4net.ioctl = v4net_ioctl;
	/*
	 * Optional timer function that is called every 200ms.
	 */
	if_v4net.timeout = 0;

	/*
	 * Here you could attach some more data your driver may need
	 */
	if_v4net.data = 0;

 #if 1

        mem4=(void*)TRAP_Mxalloc(2048+(MEMSIZE),1);
if (!mem4)
{

  c_conws("kmalloc fail\n");
  return(0);
}
c_conws ("1");

c_conws ("2");


	memset(mem4,0,2048+MEMSIZE);
#endif

c_conws ("3");
alignmem=(uint32_t)mem4;

//alignmem = ((alignmem+2047) & (ulong)0xfffff800);
if (!alignmem)
	return(0);
memset((void*)alignmem,0,MEMSIZE);

c_conws ("4");



	__asm__ __volatile__
		(
	"move.l #0,0xde0028\n\t"
	"move.l #0,0xde002C\n\t"
			);
	v4e->rx_start=alignmem;
	v4e->rx_stop=alignmem+MEMSIZE;



c_conws ("5 ");
*swposptr=((alignmem+MEMSIZE)-2048);
swposcopy=((alignmem+MEMSIZE)-2048);



	*mac1ptr = (0x80L<<8|0x06);
	*mac2ptr = (0x4L<<24|0x4L<<16|0x4L<<8|0x11);


c_conws (" done ");
v4net_install_int();
	/*
	 * Number of packets the hardware can receive in fast succession,
	 * 0 means unlimited.
	 */
	if_v4net.maxpackets = 0;

		ksprintf (message, "memory: 0x%x   ", alignmem);
		c_conws (message);
	/*
	 * Register the interface.
	 */
	if_register (&if_v4net);

/*
	 * NETINFO->fname is a pointer to the drivers file name
	 * (without leading path), eg. "v4net.xif".
	 * NOTE: the file name will be overwritten when you leave the
	 * init function. So if you need it later make a copy!
	 */
	if (NETINFO->fname)
	{
		strncpy (my_file_name, NETINFO->fname, sizeof (my_file_name));
		my_file_name[sizeof (my_file_name) - 1] = '\0';
# if 0
		ksprintf (message, "My file name is '%s'\n\r", my_file_name);
		c_conws (message);
# endif
	}
	/*
	 * And say we are alive...
	 */
c_conws ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!v4n  ");
	ksprintf (message, "v4net Eth driver v0.0 (en%d)\n\r", if_v4net.unit);
	c_conws (message);
	return 0;
}

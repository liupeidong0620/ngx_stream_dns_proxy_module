#ifndef NGX_DNS_TYPE_H
#define NGX_DNS_TYPE_H

/* Here's where the packet's first field starts. */
#define PACKET_DATABEGIN                12

/* According to RFC 1035 (2.3.4) */
#define UDP_MAXSIZE 512

/* Macros for manipulating the flags field */
#define MASK_RCODE  0x000f
#define MASK_Z      0x0040
#define MASK_RA     0x0080
#define MASK_RD     0x0100
#define MASK_TC     0x0200
#define MASK_AA     0x0400
#define MASK_OPCODE 0xe800
#define MASK_QR     0x8000

#define GET_RCODE(x)    ((x) & MASK_RCODE)
#define GET_Z(x)        (((x) & MASK_Z) >> 4)
#define GET_RA(x)       (((x) & MASK_RA) >> 7)
#define GET_RD(x)       (((x) & MASK_RD) >> 8)
#define GET_TC(x)       (((x) & MASK_TC) >> 9)
#define GET_AA(x)       (((x) & MASK_AA) >> 10)
#define GET_OPCODE(x)   (((x) & MASK_OPCODE) >> 11)
#define GET_QR(x)       (((x) & MASK_QR) >> 15)

#define SET_RCODE(x, y)     ((x) = ((x) & ~MASK_RCODE) | ((y) & MASK_RCODE))
#define SET_RA(x, y)        ((x) = ((x) & ~MASK_RA) | (((y) << 7) & MASK_RA))
#define SET_RD(x, y)        ((x) = ((x) & ~MASK_RD) | (((y) << 8) & MASK_RD))
#define SET_TC(x, y)        ((x) = ((x) & ~MASK_TC) | (((y) << 9) & MASK_TC))
#define SET_AA(x, y)        ((x) = ((x) & ~MASK_AA) | (((y) << 10) & MASK_AA))
#define SET_OPCODE(x, y)    ((x) = ((x) & ~MASK_OPCODE) | \
                             (((y) << 11) & MASK_OPCODE))
#define SET_QR(x, y)        ((x) = ((x) & ~MASK_QR) | (((y) << 15) & MASK_QR))

#define RR_LABELMAXLEN 63
#define RR_LABELSIZE (RR_LABELMAXLEN + 1)
#define RR_NAMEMAXLEN 255
#define RR_NAMESIZE (RR_NAMEMAXLEN + 1)

#define	TypeNone    0
#define	TypeA       1
#define	TypeNS      2
#define	TypeMD      3
#define	TypeMF      4
#define	TypeCNAME   5
#define	TypeSOA     6
#define	TypeMB      7
#define	TypeMG      8
#define	TypeMR      9
#define	TypeNULL    10
#define	TypePTR     12
#define	TypeHINFO   13
#define	TypeMINFO   14
#define	TypeMX      15
#define	TypeTXT     16
#define	TypeRP      17
#define	TypeAFSDB   18
#define	TypeX25         19
#define	TypeISDN        20
#define	TypeRT          21
#define	TypeNSAPPTR     23
#define	TypeSIG         24
#define	TypeKEY         25
#define	TypePX          26
#define	TypeGPOS        27
#define	TypeAAAA        28
#define	TypeLOC         29
#define	TypeNXT         30
#define	TypeEID         31
#define	TypeNIMLOC      32
#define	TypeSRV         33
#define	TypeATMA        34
#define	TypeNAPTR       35
#define	TypeKX          36
#define	TypeCERT        37
#define	TypeDNAME       39
#define	TypeOPT         41 // EDNS
#define	TypeDS          43
#define	TypeSSHFP       44
#define	TypeRRSIG       46
#define	TypeNSEC        47
#define	TypeDNSKEY      48
#define	TypeDHCID       49
#define	TypeNSEC3       50
#define	TypeNSEC3PARAM  51
#define	TypeTLSA        52
#define	TypeSMIMEA      53
#define	TypeHIP         55
#define TypeNINFO       56
#define	TypeRKEY        57
#define	TypeTALINK      58
#define	TypeCDS         59
#define	TypeCDNSKEY     60
#define	TypeOPENPGPKEY  61
#define	TypeCSYNC       62
#define	TypeSPF         99
#define	TypeUINFO       100
#define	TypeUID         101
#define	TypeGID         102
#define	TypeUNSPEC      103
#define	TypeNID         104
#define	TypeL32         105
#define	TypeL64         106
#define	TypeLP          107
#define	TypeEUI48       108
#define	TypeEUI64       109
#define	TypeURI         256
#define	TypeCAA         257
#define	TypeAVC         258

#define	TypeTKEY  249
#define	TypeTSIG  250

#define	TypeIXFR   251
#define	TypeAXFR   252
#define	TypeMAILB  253
#define	TypeMAILA  254
#define	TypeANY    255

#define	TypeTA        32768
#define	TypeDLV       32769
#define	TypeReserved  65535

	// valid Question.Qclass
#define	ClassINET   1
#define	ClassCSNET  2
#define	ClassCHAOS  3
#define	ClassHESIOD 4
#define	ClassNONE   254
#define	ClassANY    255

// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
#define	RcodeSuccess        0  // NoError   - No Error                          [DNS]
#define	RcodeFormatError    1  // FormErr   - Format Error                      [DNS]
#define	RcodeServerFailure  2  // ServFail  - Server Failure                    [DNS]
#define	RcodeNameError      3  // NXDomain  - Non-Existent Domain               [DNS]
#define	RcodeNotImplemented 4  // NotImp    - Not Implemented                   [DNS]
#define	RcodeRefused        5  // Refused   - Query Refused                     [DNS]
#define	RcodeYXDomain       6  // YXDomain  - Name Exists when it should not    [DNS Update]
#define	RcodeYXRrset        7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
#define	RcodeNXRrset        8  // NXRRSet   - RR Set that should exist does not [DNS Update]
#define	RcodeNotAuth        9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
#define	RcodeNotZone        10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
#define	RcodeBadSig         16 // BADSIG    - TSIG Signature Failure            [TSIG]
#define	RcodeBadVers        16 // BADVERS   - Bad OPT Version                   [EDNS0]
#define	RcodeBadKey         17 // BADKEY    - Key not recognized                [TSIG]
#define	RcodeBadTime        18 // BADTIME   - Signature out of time window      [TSIG]
#define	RcodeBadMode        19 // BADMODE   - Bad TKEY Mode                     [TKEY]
#define	RcodeBadName        20 // BADNAME   - Duplicate key name                [TKEY]
#define	RcodeBadAlg         21 // BADALG    - Algorithm not supported           [TKEY]
#define	RcodeBadTrunc       22 // BADTRUNC  - Bad Truncation                    [TSIG]
#define	RcodeBadCookie      23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]

// Message Opcodes. There is no 3.
#define	OpcodeQuery  0
#define	OpcodeIQuery 1
#define	OpcodeStatus 2
#define	OpcodeNotify 4
#define	OpcodeUpdate 5

char *
ngx_dns_opcode_type_string(int type);

char *
ngx_dns_rcode_type_string(int type);

char *
ngx_dns_class_type_string(int type);

char *
ngx_dns_type_string(int type);

#endif

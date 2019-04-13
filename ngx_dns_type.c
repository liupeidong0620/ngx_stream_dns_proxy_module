
#include "ngx_dns_type.h"

char *
ngx_dns_opcode_type_string(int type)
{
    switch(type) {
	case OpcodeQuery:           return "QUERY";
	case OpcodeIQuery:          return "IQUERY";
	case OpcodeStatus:          return "STATUS";
	case OpcodeNotify:          return "NOTIFY";
	case OpcodeUpdate:          return "UPDATE";
    }

    return "\0";
}

char *
ngx_dns_rcode_type_string(int type)
{
    switch(type) {
    case RcodeSuccess:          return "NOERROR";
	case RcodeFormatError:      return "FORMERR";
	case RcodeServerFailure:    return "SERVFAIL";
	case RcodeNameError:        return "NXDOMAIN";
	case RcodeNotImplemented:   return "NOTIMP";
	case RcodeRefused:          return "REFUSED";
	case RcodeYXDomain:         return "YXDOMAIN"; // See RFC 2136
	case RcodeYXRrset:          return "YXRRSET";
	case RcodeNXRrset:          return "NXRRSET";
	case RcodeNotAuth:          return "NOTAUTH";
	case RcodeNotZone:          return "NOTZONE";
	case RcodeBadSig:           return "BADSIG"; // Also known as RcodeBadVers, see RFC 6891
	//	RcodeBadVers:        "BADVERS",
	case RcodeBadKey:           return "BADKEY";
    case RcodeBadTime:          return "BADTIME";
	case RcodeBadMode:          return "BADMODE";
	case RcodeBadName:          return "BADNAME";
	case RcodeBadAlg:           return "BADALG";
	case RcodeBadTrunc:         return "BADTRUNC";
	case RcodeBadCookie:        return "BADCOOKIE";
    }

    return "\0";
}

char *
ngx_dns_class_type_string(int type)
{
    switch(type) {
	case ClassINET:   return "IN";
	case ClassCSNET:  return "CS";
	case ClassCHAOS:  return "CH";
	case ClassHESIOD: return "HS";
	case ClassNONE:   return "NONE";
	case ClassANY:    return "ANY";
    }

    return "\0";
}

char *
ngx_dns_type_string(int type)
{
    switch(type) {
        case TypeNone:      return "NONE";
        case TypeA:         return "A";
        case TypeNS:        return "NS";
        case TypeMD:        return "MD";
        case TypeMF:        return "MF";
        case TypeCNAME:     return "CNAME";
        case TypeSOA:       return "SOA";
        case TypeMB:        return "MB";
        case TypeMG:        return "MG";
        case TypeMR:        return "MR";
        case TypeNULL:      return "NULL";
        case TypePTR:       return "PTR";
        case TypeHINFO:     return "HINFO";
        case TypeMINFO:     return "MINFO";
        case TypeMX:        return "MX";
        case TypeTXT:       return "TXT";
        case TypeRP:        return "RP";
        case TypeAFSDB:     return "AFSDB";
        case TypeX25:       return "X25";
        case TypeISDN:      return "ISDN";
        case TypeRT:        return "RT";
        case TypeNSAPPTR:   return "NSAPPTR";
        case TypeSIG:       return "SIG";
        case TypeKEY:       return "KEY";
        case TypePX:        return "PX";
        case TypeGPOS:      return "GPOS";
        case TypeAAAA:      return "AAAA";
        case TypeLOC:       return "LOC";
        case TypeNXT:       return "NXT";
        case TypeEID:       return "EID";
        case TypeNIMLOC:    return "NIMLOC";
        case TypeSRV:       return "SRV";
        case TypeATMA:      return "ATMA";
        case TypeNAPTR:     return "NAPTR";
        case TypeKX:        return "KX";
        case TypeCERT:      return "CERT";
        case TypeDNAME:     return "DNAME";
        case TypeOPT:       return "OPT";  // EDNS
        case TypeDS:        return "DS";
        case TypeSSHFP:     return "SSHFP";
        case TypeRRSIG:     return "RRSIG";
        case TypeNSEC:      return "NSEC";
        case TypeDNSKEY:    return "DNSKEY";
        case TypeDHCID:     return "DHCID";
        case TypeNSEC3:     return "NSEC3";
        case TypeNSEC3PARAM: return "NSEC3PARAM";
        case TypeTLSA:      return "TLSA";
        case TypeSMIMEA:    return "SMIMEA";
        case TypeHIP:       return "HIP";
        case TypeNINFO:     return "NINFO";
        case TypeRKEY:      return "RKEY";
        case TypeTALINK:    return "TALINK";
        case TypeCDS:       return "CDS";
        case TypeCDNSKEY:   return "CNDSKEY";
        case TypeOPENPGPKEY: return "OPENPGPKEY";
        case TypeCSYNC:     return "CSYNC";
        case TypeSPF: return "SPF";
        case TypeUINFO: return "UINFO";
        case TypeUID: return "UID";
        case TypeGID: return "GID";
        case TypeUNSPEC: return "UNSPEC";
        case TypeNID: return "NID";
        case TypeL32: return "L32";
        case TypeL64: return "L64";
        case TypeLP: return "LP";
        case TypeEUI48: return "EUI48";
        case TypeEUI64: return "EUI64";
        case TypeURI: return "URI";
        case TypeCAA: return "CAA";
        case TypeAVC: return "AVC";

        case TypeTKEY: return "TKEY";
        case TypeTSIG: return "TSIG";

	// valid Question.Qtype only
        case TypeIXFR: return "IXFR";
        case TypeAXFR: return "AXFR";
        case TypeMAILB: return "MAILB";
        case TypeMAILA: return "MAILA";
        case TypeANY: return "ANY";

        case TypeTA: return "TA";
        case TypeDLV: return "DLV";
        case TypeReserved: return "RESERVED";
    }

    return "\0";
}

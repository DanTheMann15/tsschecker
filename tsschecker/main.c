//
//  main.c
//  tsschecker
//
//  Created by tihmstar on 22.12.15.
//  Copyright © 2015 tihmstar. All rights reserved.
//

#ifdef __STDC_ALLOC_LIB__
#define __STDC_WANT_LIB_EXT2__ 1
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <libfragmentzip/libfragmentzip.h>

#include "download.h"
#include "debug.h"
#include "tsschecker.h"
#include "all.h"

#define FLAG_LIST_VERSIONS			(1 << 0)
#define FLAG_LIST_DEVICES			(1 << 1)
#define FLAG_BUILDMANIFEST			(1 << 2)
#define FLAG_LATEST_VERSION			(1 << 3)
#define FLAG_SAVE_CRYPTEX_SEED		(1 << 4)
#define FLAG_SAVE_CRYPTEX_NONCE		(1 << 5)

extern int idevicerestore_debug;
extern unsigned char *base64decode(const char *buf, size_t *size);
#define reterror(code,a ...) {error(a); err = code; goto error;}

static struct option longopts[] = {
	{ "build-manifest",		required_argument,	NULL,	'm'	},
	{ "device",				required_argument,	NULL,	'd'	},
	{ "version",			required_argument,	NULL,	'v'	},
	{ "ecid",				required_argument,	NULL,	'e'	},
	{ "help",				no_argument,		NULL,	'h'	},
	{ "no-baseband",		optional_argument,	NULL,	'b'	},
	{ "ota",				no_argument,		NULL,	'o'	},
	{ "save",				no_argument,		NULL,	's'	},
	{ "latest",				no_argument,		NULL,	'l'	},
	{ "update-install",		no_argument,		NULL,	'u'	},
	{ "erase-install",		no_argument,		NULL,	'E'	},
	{ "boardconfig",		required_argument,	NULL,	'B'	},
	{ "buildid",			required_argument,	NULL,	'Z'	},
	{ "debug",				no_argument,		NULL,	'0'	},
	{ "list-devices",		no_argument,		NULL,	'1'	},
	{ "list-versions",		no_argument,		NULL,	'2'	},
	{ "save-path",			required_argument,	NULL,	'3'	},
	{ "print-tss-request",	no_argument,		NULL,	'4'	},
	{ "print-tss-response",	no_argument,		NULL,	'5'	},
	{ "beta",				no_argument,		NULL,	'6'	},
	{ "nocache",			no_argument,		NULL,	'7'	},
	{ "apnonce",			required_argument,	NULL,	'8'	},
	{ "sepnonce",			required_argument,	NULL,	'9'	},
	{ "cryptexnonce",		required_argument,	NULL,	't'	},
	{ "raw",				required_argument,	NULL,	'r'	},
	{ "bbsnum",				required_argument,	NULL,	'c'	},
	{ "server-url",			required_argument,	NULL,	'S'	},
	{ "bplist",				no_argument,		NULL,	'p'	},
	{ "generator",			required_argument,	NULL,	'g'	},
	{ "cryptexseed",		required_argument,	NULL,	'x'	},
	{ NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Checks the current TSS signing status for your target apple device and software version\n\n");
    printf("Usage: tsschecker [OPTIONS] <>\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -d, --device <model>\t\tSpecify the device by its model (eg: iPhone13,3)\n");
    printf("  -v, --version <version>\tSpecify the software version (eg: 26.6.2)\n");
    printf("  -Z  --buildid <build>\t\tSpecify the build number instead of the software version (eg: 23G90)\n");
    printf("  -B, --boardconfig <board> \tSpecify the board config instead of the device model (eg: d53pap)\n");
    printf("  -o, --ota\t\t\tCheck OTA signing status for a a given version instead of the IPSW\n");
    printf("  -b, --no-baseband\t\tDo not check the baseband signing status (Request tickets without baseband)\n");
    printf("  -m, --build-manifest\t\tSpecify the BuildManifest to use for requesting tickets (Used with -d, -B or both)\n");
    printf("  -s, --save\t\t\tSave fetched SHSH Blobs (Mostly makes sense with -e)\n");
    printf("  -u, --update-install\t\tRequest update tickets (InstallType=Update) only\n");
    printf("  -E, --erase-install\t\tRequest erase tickets (InstallType=Erase) only\n");
    printf("  -l, --latest\t\t\tUse the latest public software version instead of manually specifying one\n");
    printf("                 \t\tespecially useful with -s and -e for saving shsh blobs\n");
    printf("  -e, --ecid <ecid>\t\tSpecify the ECID to be used when requesting tickets, instead of using random ones\n");
    printf("                 \t\tECID must be either DEC or HEX eg. 5482657301265 or 0xab46efcbf71\n");
    printf("  -g, --generator <seed>\tSpecify the ApNonce seed (generator) in HEX format 16 in length (eg: 0x1111111111111111)\n\n");
    printf("  -x, --cryptexseed <seed>\t\tSpecify the Cryptex1 seed in HEX format 32 in length (eg: 0x11111111111111111111111111111111)\n\n");
    printf("  -8  --apnonce <nonce>\t\tSpecify the ApNonce instead of using random ones\n\t\t\t\t(Required when saving blobs for arm64e devices with a matching generator)\n\n");
    printf("  -9  --sepnonce <nonce>\tSpecify the SepNonce instead of using random ones (not required for saving blobs)\n");
    printf("  -t  --cryptexnonce <nonce>\tSpecify the Cryptex1 Nonce (Required for saving usable cryptex blobs)\n");
    printf("  -c  --bbsnum <snum>\t\tSpecify the Baseband Serial Number in HEX to save BBTickets (Only required when saving baseband tickets)\n\n");
    printf("  -3  --save-path <path>\tSpecify the output path for saving fetched shsh blobs\n");
    printf("  -p  --bplist\t\t\tSave SHSH blobs in a binary plist for smaller filesize (Used with -s)\n");
    printf("  -S  --server-url <url>\tSpecify the TSS server URL for requesting tickets\n");
    printf("  -6  --beta\t\t\tRequest tickets for beta software instead of release (Used with -o)\n");
    printf("  -1  --list-devices\t\tList all known apple devices\n");
    printf("  -2  --list-versions\t\tList all known software versions\n");
    printf("  -7  --nocache \t\tIgnore caches and re-download required files\n");
    printf("  -4  --print-tss-request\tPrint the request that will be sent to the TSS server\n");
    printf("  -5  --print-tss-response\tPrint the response that comes from the TSS server\n");
    printf("  -r  --raw\t\t\tSend a raw file to the TSS server (Useful for debugging)\n");
    printf("  -0  --debug\t\t\tPrint extra TSS info (Useful for debugging)\n\n");
}

int64_t parseECID(const char *ecid){
    const char *ecidBK = ecid;
    int isHex = 0;
    int64_t ret = 0;
    
    //in case hex ecid only contains digits, specify with 0x1235
    if (strncmp(ecid, "0x", 2) == 0){
        isHex = 1;
        ecidBK = ecid+2;
    }
    
    while (*ecid && !isHex) {
        char c = *(ecid++);
        if (c >= '0' && c<='9') {
            ret *=10;
            ret += c - '0';
        }else{
            isHex = 1;
            ret = 0;
        }
    }
    
    if (isHex) {
        while (*ecidBK) {
            char c = *(ecidBK++);
            ret *=16;
            if (c >= '0' && c<='9') {
                ret += c - '0';
            }else if (c >= 'a' && c <= 'f'){
                ret += 10 + c - 'a';
            }else if (c >= 'A' && c <= 'F'){
                ret += 10 + c - 'A';
            }else{
                return 0; //ERROR Parsing failed
            }
        }
    }
    
    return ret;
}

char *parseNonce(const char *nonce, size_t *parsedLen){
    char *ret = NULL;
    size_t retSize = 0;
    if (parseHex(nonce, parsedLen, NULL, &retSize))
        return NULL;
    ret = malloc(retSize);
    if (parseHex(nonce, parsedLen, ret, &retSize))
        return NULL;
    
    return ret;
}

int main(int argc, const char * argv[]) {
    int err = 0;
    int isSigned = 0;
    printf("tsschecker version: "TSSCHECKER_VERSION_MAJOR"."TSSCHECKER_VERSION_MINOR"."TSSCHECKER_VERSION_COUNT"."TSSCHECKER_VERSION_PATCH"-"TSSCHECKER_VERSION_SHA"-"TSSCHECKER_BUILD_TYPE"\n");
    printf("%s\n",fragmentzip_version());
    
    dbglog = 1;
    idevicerestore_debug = 0;
    save_shshblobs = 0;
    save_bplist = 0;
    int optindex = 0;
    int opt = 0;
    long flags = 0;
    
    char *buildmanifest = 0;
    char *ecid = 0;
    
    char *apnonce = 0;
    char *sepnonce = 0;
    char *cryptexnonce = 0;
    char *bbsnum = 0;
    t_devicevals devVals = {0};
    t_swVersion versVals = {0};
    char *firmwareJson = NULL;
    jssytok_t *firmwareTokens = NULL;
    
    const char *rawFilePath = NULL;
    const char *serverUrl = NULL;
    
    if (argc == 1){
        cmd_help();
        return -1;
    }

    while ((opt = getopt_long(argc, (char* const *)argv, "hd:v:Z:B:e:g:x:b::m:3:8:9:t:r:c:S:uElso0124567p", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h': // long option: "help"; can be called as short option
                cmd_help();
                return 0;
            case 'd': // long option: "device"; can be called as short option
                devVals.deviceModel = strdup(optarg);
                break;
            case 'v': // long option: "version"; can be called as short option
                if (versVals.version) reterror(-9, "[TSSC] Parsing parameter failed\n");
                versVals.version = strdup(optarg);
                break;
            case 'Z': // long option: "buildid"; can be called as short option
                versVals.buildID = strdup(optarg);
                break;
            case 'B': // long option: "boardconfig"; can be called as short option
                devVals.deviceBoard = strdup(optarg);
                break;
            case 'e': // long option: "ecid"; can be called as short option
                ecid = optarg;
                break;
            case 'g': // long option: "generator"; can be called as short option
                if (optarg[0] != '0' && optarg[1] != 'x')
                    goto failparse;
                devVals.generator[0] = '0';
                devVals.generator[1] = 'x';
                devVals.generator[sizeof(devVals.generator)-1] = '\0';
                devVals.generator[0+2] = tolower(optarg[0+2]);
                for (int i=0;i<16; i++){
                    devVals.generator[i+2] = tolower(optarg[i+2]);
                    if (!isdigit(optarg[i+2]) && ((int)devVals.generator[i+2] < 'a' || devVals.generator[i+2] > 'f'))
                        failparse:
                        reterror(-10, "[TSSC] Parsing generator \"%s\" failed\n",optarg);

                }
                info("[TSSC] User specified generator \"%s\"\n",devVals.generator);
                break;
            case 'x': // long option: "cryptexseed"; can be called as short option
                if (optarg[0] != '0' && optarg[1] != 'x')
                    goto failparse_c;
                devVals.cryptexseed[0] = '0';
                devVals.cryptexseed[1] = 'x';
                devVals.cryptexseed[sizeof(devVals.cryptexseed)-1] = '\0';
                devVals.cryptexseed[0+2] = tolower(optarg[0+2]);
                for (int i=0;i<32; i++){
                    devVals.cryptexseed[i+2] = tolower(optarg[i+2]);
                    if (!isdigit(optarg[i+2]) && ((int)devVals.cryptexseed[i+2] < 'a' || devVals.cryptexseed[i+2] > 'f'))
                    failparse_c:
                        reterror(-10, "[TSSC] Parsing cryptex seed \"%s\" failed\n",optarg);

                }
                flags |= FLAG_SAVE_CRYPTEX_SEED;
                info("[TSSC] User specified cryptex seed \"%s\"\n",devVals.cryptexseed);
                break;
            case 'b': // long option: "no-baseband"; can be called as short option
                if (optarg) {
                  errno = 0;
                  versVals.basebandMode = (int)strtol(optarg, NULL, 10);
                  if(errno != 0) {
                    versVals.basebandMode = kBasebandModeWithoutBaseband;
                  }
                } else {
                  versVals.basebandMode = kBasebandModeWithoutBaseband;
                }
                break;
            case 'u': // long option: "update-install"; can be called as short option
                devVals.installType = kInstallTypeUpdate;
                update_install = 1;
                if (devVals.installType)
                    printf("[TSSC] Manually setting install type = Update\n");
                break;
            case 'E': // long option: "erase-install"; can be called as short option
                devVals.installType = kInstallTypeErase;
                erase_install = 1;
                if (devVals.installType)
                    printf("[TSSC] Manually setting install type = Erase\n");
                break;
            case 'l': // long option: "latest"; can be called as short option
                flags |= FLAG_LATEST_VERSION;
                break;
            case 's': // long option: "save"; can be called as short option
                save_shshblobs = 1;
                break;
            case 'o': // long option: "ota"; can be called as short option
                versVals.isOta = 1;
                break;
            case 'm': // long option: "build-manifest"; can be called as short option
                flags |= FLAG_BUILDMANIFEST;
                buildmanifest = optarg;
                break;
            case '0': // long option: "debug"; can be called as short option
                idevicerestore_debug = 1;
                tss_set_print_tss_request(1);
                tss_set_print_tss_response(1);
                tss_set_debug_level(3);
                break;
            case '1': // long option: "list-devices"; can be called as short option
                flags |= FLAG_LIST_DEVICES;
                break;
            case '2': // long option: "list-versions"; can be called as short option
                flags |= FLAG_LIST_VERSIONS;
                break;
            case '3': // long option: "save-path"; can be called as short option
                shshSavePath = optarg;
                break;
            case '4': // long option: "print-tss-request"; can be called as short option
                tss_set_print_tss_request(1);
                break;
            case '5': // long option: "print-tss-response"; can be called as short option
                tss_set_print_tss_response(1);
                break;
            case '6': // long option: "beta"; can be called as short option
                versVals.useBeta = 1;
                break;
            case '7': // long option: "nocache"; can be called as short option
                nocache = 1;
                break;
            case '8': // long option: "apnonce"; can be called as short option
                apnonce = optarg;
                break;
            case '9': // long option: "sepnonce"; can be called as short option
                sepnonce = optarg;
                break;
            case 't': // long option: "cryptexnonce"; can be called as short option
                cryptexnonce = optarg;
                flags |= FLAG_SAVE_CRYPTEX_NONCE;
                break;
            case 'r': // long option: "raw"; can be called as short option
                rawFilePath = optarg;
                idevicerestore_debug = 1;
                tss_set_print_tss_request(1);
                tss_set_print_tss_response(1);
                tss_set_debug_level(3);
                break;
            case 'c': // long option: "bbsnum"; can be called as short option
                bbsnum = optarg;
                break;
            case 'S': // long option: "server-url"; can be called as short option
                serverUrl = optarg;
                break;
            case 'p': // long option: "bplist"; can be called as short option
                save_bplist = 1;
                break;
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (rawFilePath) {
        printf("unsupported");
        return 1;
        // char *buf = NULL;
        // size_t bufSize = 0;
        // FILE *f = fopen(rawFilePath, "rb");
        // if (!f)
        //     reterror(-100, "[TSSC] failed to read rawfile at \"%s\"\n",rawFilePath);
        // fseek(f, 0, SEEK_END);
        // bufSize = ftell(f);
        // fseek(f, 0, SEEK_SET);
        // buf = (char*)malloc(bufSize+1);
        // fread(buf, 1, bufSize, f);
        // fclose(f);
        
        // printf("Sending TSS request:\n%s",buf);
        // char *rsp = tss_request_send_raw(buf, serverUrl, (int*)&bufSize);

        // printf("TSS server returned:\n%s\n",rsp);
        // free(rsp);
        // return 0;
    }

    if (devVals.deviceBoard)
        for (int i=0; i<strlen(devVals.deviceBoard); i++)
            devVals.deviceBoard[i] = tolower(devVals.deviceBoard[i]);
    
    if (!devVals.deviceModel){
        if (devVals.deviceBoard){
            char *tmp = NULL;
            if ((tmp = (char*)getModelFromBoardconfig(devVals.deviceBoard)))
                devVals.deviceModel = strdup(tmp);
            else
                reterror(-25, "[TSSC] Unrecognized boardconfig\n[TSSC] If you are using --boardconfig for an unknown device, try also specifying the device model with -d.\n");
        }
    }
    
    if (devVals.deviceModel) {
        for (char *c = devVals.deviceModel; *c; c++)
            *c = tolower(*c); //make devicemodel lowercase
        //make devicemodel look nice. This is completely optional
        if (*devVals.deviceModel == 'i')
            devVals.deviceModel[1] = toupper(devVals.deviceModel[1]);
        else
            devVals.deviceModel[0] = toupper(devVals.deviceModel[0]);
    }
    
    if (ecid) {
        if ((devVals.ecid = parseECID(ecid)) == 0){
            reterror(-7, "[TSSC] User specified ECID=%s, but parsing failed\n",ecid);
        }else{
            info("[TSSC] User specified ECID to use, parsed \"%s\" to dec:%lld hex:%llx\n",ecid,devVals.ecid,devVals.ecid);
        }
    }
    
    if (apnonce) {
        if ((devVals.apnonce = parseNonce(apnonce,&devVals.parsedApnonceLen)) ){
            info("[TSSC] User specified ApNonce to use, parsed \"%s\" to hex:",apnonce);
            unsigned char *tmp = (unsigned char*)devVals.apnonce;
            for (int i=0; i< devVals.parsedApnonceLen; i++) info("%02x",*tmp++);
            info("\n");
        }else{
            reterror(-7, "[TSSC] User specified ApNonce=%s, but parsing failed\n",apnonce);
        }
    }
    
    if (sepnonce) {
        if ((devVals.sepnonce = parseNonce(sepnonce,&devVals.parsedSepnonceLen)) ){
            info("[TSSC] User specified SepNonce to use, parsed \"%s\" to hex:",sepnonce);
            unsigned char *tmp = (unsigned char*)devVals.sepnonce;
            for (int i=0; i< devVals.parsedSepnonceLen; i++) info("%02x",*tmp++);
            info("\n");
        }else{
            reterror(-7, "[TSSC] User specified SepNonce=%s, but parsing failed\n",sepnonce);
        }
    }
    if((flags & FLAG_SAVE_CRYPTEX_NONCE) == FLAG_SAVE_CRYPTEX_NONCE) {
      if(!(flags & FLAG_SAVE_CRYPTEX_SEED)) {
        reterror(-7, "[TSSC] Cryptex seed is required for saving Cryptex1 blobs\n");
      }
    }
    if((flags & FLAG_SAVE_CRYPTEX_SEED) == FLAG_SAVE_CRYPTEX_SEED) {
      if(!(flags & FLAG_SAVE_CRYPTEX_NONCE)) {
        reterror(-7, "[TSSC] Cryptex nonce is required for saving Cryptex1 blobs\n");
      }
    }
    if (cryptexnonce) {
      if ((devVals.cryptexnonce = parseNonce(cryptexnonce,&devVals.parsedCryptexnonceLen)) ){
        info("[TSSC] specified Cryptex Nonce to use, parsed \"%s\" to hex:",cryptexnonce);
        unsigned char *tmp = (unsigned char*)devVals.cryptexnonce;
        for (int i=0; i< devVals.parsedCryptexnonceLen; i++) info("%02x",*tmp++);
        info("\n");
      }else{
        reterror(-7, "[TSSC] User specified Cryptex Nonce=%s, but parsing failed\n",cryptexnonce);
      }
    }
    
    if (bbsnum) {
        t_bbdevice bbinfo = getBBDeviceInfo(devVals.deviceModel);
        if (bbinfo->bbsnumSize == 0) {
            reterror(-8, "[TSSC] This device has no baseband, so it does not make sense to provide any BbSNUM.\n");
        }

        if (*bbsnum == '=') bbsnum++; // fix -c=VALUE
        devVals.bbsnumSize = 100;
        if (strncasecmp(bbsnum, "0x", 2) == 0) { // don't attempt base64 if hex prefix
          if (!(devVals.bbsnum = (uint8_t *)parseNonce(bbsnum+2, &devVals.bbsnumSize))) {
            reterror(-7, "[TSSC] User specified BbSNUM=%s, but parsing failed\n", bbsnum);
          }
        } else if(!(devVals.bbsnum = (unsigned char *)base64decode(bbsnum, &devVals.bbsnumSize)) || (devVals.bbsnumSize != bbinfo->bbsnumSize) || !devVals.bbsnumSize || devVals.bbsnumSize == 100) {
          if (!(devVals.bbsnum = (uint8_t *)parseNonce(bbsnum, &devVals.bbsnumSize))) {
            reterror(-7, "[TSSC] User specified Baseband Serial Number=%s, but parsing failed\n", bbsnum);
          }
        }

        info("[TSSC] User specified Baseband Serial Number to use, parsed \"%s\" to hex:", bbsnum);
        unsigned char *tmp = devVals.bbsnum;
        for (int i=0; i< devVals.bbsnumSize; i++) info("%02x", *tmp++);
        info("\n");

        if (bbinfo->bbsnumSize != devVals.bbsnumSize) {
            reterror(-8, "[TSSC] BbSNUM length for this device should be %d, but you gave one of length %d\n", (int)bbinfo->bbsnumSize,
                     (int)devVals.bbsnumSize);
        }
    } else {
      if(versVals.basebandMode == kBasebandModeOnlyBaseband || versVals.basebandMode == kBasebandModeWithBaseband) {
        reterror(-7, "[TSSC] No Baseband Serial Number was specified, cannot save usable baseband tickets.\n\nPlease run ideviceinfo -k \"BasebandSerialNumber\" to get your Baseband Serial Number and try again\n");
      }
    }
    
    if (!buildmanifest) { //no need to get firmwares/ota json if specifying buildmanifest manually
    reparse:
        firmwareJson = (versVals.isOta) ? getOtaJson() : getFirmwareJson();
        if (!devVals.installType) //only set this if installType wasn't set manually
            devVals.isUpdateInstall = (versVals.isOta); //there are no erase installs over OTA
        if (!firmwareJson) reterror(-6,"[TSSC] Could not get firmwares.json\n");
        
        long cnt = parseTokens(firmwareJson, &firmwareTokens);
        if (cnt < 1){
            if (!nocache){
                warning("[TSSC] Error parsing cached %s.json. Trying to redownload\n",(versVals.isOta) ? "ota" : "firmwares");
                nocache = 1;
                goto reparse; //in case cached json is corrupt, try to redownload and reparse one more time.
            }
            reterror(-2,"[TSSC] Parsing %s.json failed\n",(versVals.isOta) ? "ota" : "firmwares");
        }
    }

    if (flags & FLAG_LATEST_VERSION && !versVals.version) {
        int versionCnt = 0;
        int i = 0;
            
        char **versions = getListOfVersionsForDevice(firmwareTokens, devVals.deviceModel, versVals.isOta, &versionCnt, versVals.useBeta);
        if (!versionCnt) reterror(-8, "[TSSC] Could not find the latest software version for your device. If you are using --boardconfig for an unknown device, try also specifying the device model with -d ota=%d\n",versVals.isOta);
        char *bpos = NULL;
        while((bpos = strstr(versVals.version = strdup(versions[i++]),"[B]")) != 0){
            if (versVals.useBeta) break;
            free((char*)versVals.version);
            if (--versionCnt == 0) reterror(-9, "[TSSC] Automatic software selection couldn't find any non-beta version\n");
        }
        info("[TSSC] Selecting the latest available software version: %s\n",versVals.version);
        if (bpos) *bpos= '\0';
        if (versions) free(versions[versionCnt-1]),free(versions);
    }
    
    if (flags & FLAG_LIST_DEVICES) {
        printListOfDevices(firmwareTokens);
    }else if (flags & FLAG_LIST_VERSIONS){
        if (!devVals.deviceModel)
            reterror(-3,"[TSSC] Please specify a device for this option, use -h for more help.\n");

        printListOfVersionsForDevice(firmwareTokens, devVals.deviceModel, versVals.isOta);
    }else{
        //request ticket
        if (buildmanifest) {
            isSigned = isManifestSignedForDevice(buildmanifest, &devVals, &versVals, serverUrl);

        }else{
            if (!devVals.deviceModel) reterror(-3,"[TSSC] Please specify a device for this option, use -h for more help.\n");
            if (!versVals.version && !versVals.buildID) reterror(-5,"[TSSC] Please specify a version or build number for this option, use -h for more help.\n");
            
            isSigned = isVersionSignedForDevice(firmwareTokens, &versVals, &devVals, serverUrl);
        }
        
        if (isSigned >=0) printf("\n%s %s for device %s %s being signed!\n",(versVals.buildID) ? "Build" : "Software version" ,(versVals.buildID ? versVals.buildID : versVals.version),devVals.deviceModel, (isSigned) ? "Is" : "Is NOT");
        else{
            putchar('\n');
            reterror(-69, "[TSSC] Checking TSS status failed\n");
        }
    }
    
error:
    if (devVals.deviceBoard) free(devVals.deviceBoard);
    if (devVals.deviceModel) free(devVals.deviceModel);
    if (devVals.apnonce) free(devVals.apnonce);
    if (devVals.sepnonce) free(devVals.sepnonce);
    if (devVals.cryptexnonce) free(devVals.cryptexnonce);
    if (devVals.bbsnum) free(devVals.bbsnum);
    if (firmwareJson) free(firmwareJson);
    if (firmwareTokens) free(firmwareTokens);
    return err ? err : !isSigned;
#undef reterror
}

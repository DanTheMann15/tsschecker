# tsschecker  
tsschecker is a powerful tool to check TSS signing status of various devices and iOS/iPadOS/tvOS/watchOS versions.

## Features  
* Allows you to get lists of all devices as well as all Firmwares and OTA versions for a specific device.
* Can check signing status for any firmware version (by specifying a `BuildManifest.plist`).
* Works without specifying any device relevant values to check signing status, but can be used to save blobs when given an ECID and the option --print-tss-response (although there are better tools to do this).

tsschecker is not only meant to be used to check firmware signing status, but also to explore Apple's TSS servers.
By using all of its customization possibilities, you might discover a combination of devices and iOS versions that is now getting signed but wasn't getting signed before. 

# About nonces:
## recommended generators for saving tickets:
* `0xbd34a880be0b53f3` // used on Electra & Chimera jailbreaks
* `0x1111111111111111` // used on unc0ver jailbreak

## Nonce Entangling (Apple A12/S4 and newer)
Newer devices, like the iPhone XR or the Apple Watch Series 4 have nonce-entangling enabled.

this means the nonces generated by your device is now also UID derived, and consequently device-specific.<br>to save usable tickets for a newer device, you need to get the nonce that your device actually generates from your generator.

for information on how to get your actual boot nonce, [see this post on r/jailbreak](https://www.reddit.com/r/jailbreak/comments/cssh8f/tutorial_easiest_way_to_save_blobs_on_a12/).

## Nonce Collisions:

the Nonce Collision method only works on a few firmwares and devices, and isn't reliable.<br>it's better to save a ticket with a generator and use the [checkm8](https://github.com/axi0mx/ipwndfu) bootrom exploit.

Recovery Nonce Collisions only occur on a few iOS versions, like iOS 9.3.3 and iOS 10.1-10.2 on the iPhone 5s<br>and is not reliable as once you update, nonces will either generate differently or not collide anymore.

DFU Nonce Collisions commonly occur on any device using A7 and A8 chipsets, regardless of iOS version.<br>and is much more reliable than using recovery collisions.

# Build
Install dependencies

* Buildsystem:
  * autoconf
  * automake
  * libtool
  * m4
  * pkg-config

* Tihmstar's tools:
  * [libgeneral](https://github.com/tihmstar/libgeneral)
  * [libfragmentzip](https://github.com/tihmstar/libfragmentzip)

* External:
  * [libcurl](https://curl.haxx.se/libcurl/)
  * [libirecovery](https://github.com/libimobiledevice/libirecovery)
  * [libplist](https://github.com/libimobiledevice/libplist)
  * [openssl](https://www.openssl.org/) or commonCrypto on macOS/OS X
  
* Submodules:
  * [jssy](https://github.com/tihmstar/jssy)
  
* Bundled libs, (not required to be installed manually):
  * [tss](https://github.com/libimobiledevice)

To compile, run:

```bash
./autogen.sh
make
sudo make install
```

# Help  
Usage: `tsschecker [OPTIONS]`

Example: `tsschecker -d iPhone10,1 -B D20AP -e [ECID] -i 13.4.1 --generator 0x1111111111111111 -s`

| option (short) | option (long)             | description                                                                       |
|----------------|---------------------------|-----------------------------------------------------------------------------------|
|  `-h`          | `--help`                  | prints usage information                                                          |        
|  `-d`          | `--device MODEL`          | specify device by its model (eg. `iPhone8,1`)                                     |
|  `-i`          | `--ios VERSION`           | specify firmware version (eg. `13.4.1`)                                                 |
|  `-Z`	   | `--buildid BUILD `	| specific buildid instead of firmware version (eg. `17E255`)							               |
|  `-B` 	   | `--boardconfig BOARD `	   | specific boardconfig instead of device model (eg. `n71ap`)						             |
|  `-o`          | `--ota`	                 | check OTA signing status, instead of normal restore                               |
|  `-b`          | `--no-baseband`           | don't check baseband signing status. Request tickets without baseband            |
|  `-m`          | `--build-manifest`   | manually specify a BuildManifest (can be used with `-d`)                           | 
|  `-s`          | `--save`		     		       | save fetched shsh blobs (mostly makes sense with -e)                              |
|  `-u`          | `--update-install         `| request update tickets instead of erase                          |  
|  `-l`	   | `--latest`  				       | use the latest public firmware version instead of manually specifying one<br/>especially useful with `-s` and `-e` for saving signing tickets                                                                                              |
|  `-e`          | `--ecid ECID`	         | manually specify ECID to be used for fetching blobs, instead of using random ones.<br/>ECID must be either DEC or HEX eg. `5482657301265` or `ab46efcbf71`                                                          |
|  `-g`          | `--generator GEN`        | manually specify generator in format 0x%%16llx                                                                                                        |
|      			     | `--apnonce NONCE`   		   | manually specify ApNonce instead of using random ones (not required for saving signing tickets) |
|      			     | `--sepnonce NONCE`        | manually specify SepNonce instead of using random ones (not required for saving signing tickets) 		                                                                                                                                  |
|                           | `--bbsnum SNUM`        | manually specify BbSNUM in HEX to save valid BBTickets (not required for saving blobs)                                                                                                                                   |
|      			     | `--save-path PATH`        | specify path for saving shsh blobs 		 											 |
|                |`--beta`	             | request ticket for a beta instead of normal release (use with `-o`)                |
|                |`--list-devices`          | list all known devices                                                            |
|                |`--list-ios`	             | list all known firmware versions                                                       |
|                |`--nocache`       	     | ignore caches and re-download required files                                      |
|                |`--print-tss-request`      | print the TSS request that will be sent to Apple                                      |
|                |`--print-tss-response`     | print the TSS response that comes from Apple                                  |
|                |`--raw`     | send raw file to Apple's TSS server (useful for debugging)                                 |

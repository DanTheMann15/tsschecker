# tsschecker  
A Powerful tool to check TSS signing status on combinations of various apple devices and firmware versions.

## Features  
* Supports: Apple TV, Apple Watch, HomePod, iPad, iPhone, iPod touch, M1 Macs and the T2 Coprocessor.
* Allows you to get lists of supported apple devices as well as Firmwares and OTA versions for any specified apple device.
* Can check signing status for any firmware version by specifying either a firmware version or a BuildManifest.
* Works without specifying any device relevant values to check signing status, but can be used to save blobs when given an ECID and the option --print-tss-response (although there are better tools to do this).

tsschecker is not only meant to be used to check firmware signing status, but also to explore Apple's TSS servers.<br/>
By using all of its customization possibilities, you might discover a combination of devices and firmware versions that is getting signed but wasn't getting signed before. 

# About Nonces:
A [Nonce](https://wikipedia.org/wiki/Cryptographic_nonce) ("Number-used-ONCE") is a randomly generated value that is used to randomize apple's signed hash blobs.

it is created by the device with a nonce seed (generator) and then hashes that seed to create the nonce.<br/>On arm64e devices the nonce is also encrypted with the device's UID Key, see "Nonce Entangling" for more details.

## Recommended nonce-seeds (Generators) for saving tickets:
* `0xbd34a880be0b53f3` // default on the [Electra](https://coolstar.org/electra/), [Chimera](https://chimera.coolstar.org/) and [Odyssey](https://theodyssey.dev/) jailbreak apps.
* `0x1111111111111111` // default on the [unc0ver](https://unc0ver.dev) jailbreak app.

## Nonce Entangling (arm64e devices)
arm64e devices such as the iPhone XR, Apple Watch Series 4 and all newer devices have nonce-entangling.

Nonce Entangling works by further randomizing the boot nonce by encrypting it with the device's [unique ID key](https://www.theiphonewiki.com/wiki/UID_key),<br/>
making the nonce created from the generator specific to that device only.

To save tickets for an arm64e device, you must get the boot nonce that the device creates from your generator,<br/>
the simpliest way to get a nonce/generator pair is to use airsquared's [blobsaver](https://github.com/airsquared/blobsaver) tool and read them from the device.

if you need more information, [see this post on r/jailbreak](https://www.reddit.com/r/jailbreak/comments/cssh8f/tutorial_easiest_way_to_save_blobs_on_a12/).

## Nonce Collisions:

the Nonce Collision method only works on a few firmwares and devices, and is not reliable and not recommended.<br/>it's a lot better to save a ticket with a generator and use the [checkm8](https://github.com/axi0mx/ipwndfu) bootrom exploit or a nonce setter.

Recovery Nonce Collisions only occur on a few iOS versions, like iOS 9.3.3 and iOS 10.1-10.2 on the iPhone 5s<br/>and is not reliable as once you update, your device will almost-certainly not collide nonces anymore.

DFU Nonce Collisions on the other hand, very commonly occur on any device using A7 and A8 chipsets regardless of iOS version and is MUCH more reliable than using recovery collisions.

# Build
Install or Compile dependencies

* Buildsystem:
  * autoconf
  * autoconf-archive
  * autogen
  * automake
  * libtool
  * m4
  * make
  * pkg-config

* Tihmstar's libs:
  * [libgeneral](https://github.com/tihmstar/libgeneral)
  * [libfragmentzip](https://github.com/tihmstar/libfragmentzip)

* External libs:
  * [libcurl](https://curl.haxx.se/libcurl/)
  * [libirecovery](https://github.com/libimobiledevice/libirecovery)
  * [libplist](https://github.com/libimobiledevice/libplist)
  * [libzip](https://libzip.org/)
  * [openssl](https://www.openssl.org/) (or you can use CommonCrypto on macOS/OS X)
  * [zlib](https://zlib.net/)
  
* Submodules:
  * [jssy](https://github.com/tihmstar/jssy)
  
* Bundled libs, (not required to be installed manually):
  * [tss](https://github.com/libimobiledevice)

To compile, run:

```bash
./autogen.sh
make
make install
```

# Help  
Usage: `tsschecker [OPTIONS]`

Example: `tsschecker -d iPhone10,3 -B D22AP -e 5482657301265 -i 15.4.1 --generator 0x1111111111111111 -s`

| option (short)	| option (long)					| description																																																													|
|	------------------	|	------------------------------	|	---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|
|	`-h`					| `--help`								| prints usage information																																																								|        
|	`-d`					| `--device MODEL`			| specify device by its model (eg. iPhone10,3)																																																|
|	`-i`					| `--ios VERSION`				| specify firmware version (eg. 15.4.1)																																																			|
|	`-Z`					| `--buildid BUILD `				| specify buildid instead of firmware version (eg. 19E258)																																											|
|	`-B`					| `--boardconfig BOARD `	| specify boardconfig instead of device model (eg. d22ap)																																											|
|	`-o`					| `--ota`								| check OTA signing status, instead of normal restore																																													|
|	`-b`					| `--no-baseband`				| don't check baseband signing status. Request tickets without baseband																																					|
|	 `-m`				| `--build-manifest`			| manually specify a BuildManifest (can be used with -d)																																											| 
|	`-s`					| `--save`							| save fetched shsh blobs (mostly makes sense with -e)																																												|
|	`-u`					| `--update-install`				| request update tickets instead of erase																																																		|  
|	`-l`					| `--latest`							| use the latest public firmware version instead of manually specifying one<br/>especially useful with -s and -e for saving shsh blobs												|
|	`-e`					| `--ecid ECID`					| manually specify ECID to be used for fetching blobs, instead of using random ones<br/>ECID must be either DEC or HEX eg. 5482657301265 or 0xab46efcbf71		|
|	`-g`					| `--generator GEN`			| manually specify generator in HEX format 16 in length (eg. 0x1111111111111111)																																|
|							| `--apnonce NONCE`			| manually specify ApNonce instead of using random ones<br/>(required when saving blobs for arm64e devices with matching generator)											|
|							| `--sepnonce NONCE`		| manually specify SEP Nonce instead of using random ones (not required for saving blobs)																														|
|							| `--bbsnum SNUM`			| manually specify BbSNUM in HEX to save valid BBTickets (not required for saving blobs)																														|
|							| `--save-path PATH`			| specify output path for saving shsh blobs																																																	|
|							| `--server-url URL`				| manually specify TSS server URL																																																					|
|							| `--bplist`							| save fetched blobs in a binary plist (.bshsh2 format)																																													|
|							| `--beta`								| request tickets for a beta instead of normal release (use with -o)																																							|
|							| `--list-devices`					| list known devices from firmwares.json																																																		|
|							| `--list-versions`				| list all known firmware versions for the specified device																																											|
|							| `--nocache`						| ignore caches and re-download required files																																															|
|							| `--print-tss-request`			| print the TSS request that will be sent to Apple																																															|
|							| `--print-tss-response`		| print the TSS response that comes from Apple																																															|
|							| `--raw`								| send raw file to Apple's TSS server (useful for debugging)																																										|

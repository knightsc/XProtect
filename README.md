# XProtect

XProtect is part of the macOS Gatekeeper security feature. Gatekeeper builds upon the file quarantine functionality introduced in macOS 10.4 and was introduced in macOS 10.7.3. It enforces code signing and verifies downloaded applications before allowing them to run. XProtect additionally provides the ability to have signature based blacklisting of malicious applications.

This repo contains historical releases of the XProtect configuration data. Originally this configuration data was delivered via a specific URL just for XProtect:

https://configuration.apple.com/configurations/macosx/xprotect/1/clientConfiguration.plist 
https://configuration.apple.com/configurations/macosx/xprotect/2/clientConfiguration.plist
https://configuration.apple.com/configurations/macosx/xprotect/3/clientConfiguration.plist 

Originally this data was stored in `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources`. Currently XProtect is released through the normal Apple update catalog mechanisms. So for instance in this catalog:

https://swscan.apple.com/content/catalogs/others/index-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz

There is a package entitled `XProtectPlistConfigData.pkg` which installs the config data into `/System/Library/CoreServices/XProtect.bundle/Contents/Resources`

## XProtect.meta.plist

## XProtect.plist

## XProtect.yara

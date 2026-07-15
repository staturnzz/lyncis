#!/bin/bash
# only for use when installing the .tar directly

if [ "$(id -u)" -ne 0 ]; then
  echo "install script must ran as root"
  exit 1
fi

# check if installing via sshrd or on device
if [ -e "/mnt1/usr/bin" ]; then
    cd /mnt1
else
    cd /
fi

mv System/Library/LaunchDaemons/* Library/LaunchDaemons
mv Library/LaunchDaemons/com.apple.CrashHousekeeping.plist System/Library/LaunchDaemons
mv Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist System/Library/LaunchDaemons
mv Library/LaunchDaemons/com.apple.jetsamproperties.*.plist System/Library/LaunchDaemons

mv Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist.backup
mv Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist.backup

mv -v usr/libexec/CrashHousekeeping usr/libexec/CrashHousekeeping.backup
ln -s /aquila usr/libexec/CrashHousekeeping

chmod 0777 aquila
chown 0:0 aquila
chmod 0755 usr/libexec/CrashHousekeeping
chown 0:0 usr/libexec/CrashHousekeeping

exit 0
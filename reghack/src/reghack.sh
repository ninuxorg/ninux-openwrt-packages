#!/bin/sh

hackMe="ath cfg80211"

cd /tmp

for module in ${hackMe}
do
	cp /lib/modules/*/${module}.ko /tmp
	/usr/bin/reghack ${module}.ko
	mv ${module}.ko /lib/modules/*/
done

rmmod ath9k ath9k_common ath9k_hw ath mac80211 cfg80211 compat

insmod compat
insmod cfg80211 
insmod mac80211
insmod ath 
insmod ath9k_hw 
insmod ath9k_common 
insmod ath9k


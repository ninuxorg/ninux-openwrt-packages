# 
# Copyright (C) 2010-2012 ninux.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-ng
PKG_VERSION:=2

include $(INCLUDE_DIR)/package.mk

define Package/ninux-ng
  SECTION:=utils
  TITLE:=Ninux NG Firmware
  MAINTAINER:=contatti@ninux.org
  #selected by default when installed inside OpenWrt..
  DEFAULT=y
  DEPENDS:=+olsrd-ninux-all +iw +tinc +kmod-ipv6 +tc +ip +kmod-ip6tables \
	+iptables-mod-hashlimit +iptables-mod-conntrack +iperf +ip6tables-utils \
	+ip6tables +nodogsplashninux +ip +iptraf +iwinfo +tcpdump +radvd
  #this is a meta package suitable for any archs...
  PKG_ARCH:=all
endef

define Package/ninux-ng/description
   Ninux NG Firmware - meta package
endef

define Build/Compile
endef

define Package/ninux-ng/install
	$(INSTALL_DIR) $(1)/
	$(CP) -r ./files/* $(1)/
endef

$(eval $(call BuildPackage,ninux-ng))

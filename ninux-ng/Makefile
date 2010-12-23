# 
# Copyright (C) 2010 ninux.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-ng
PKG_VERSION:=1

include $(INCLUDE_DIR)/package.mk

define Package/ninux-ng
  SECTION:=utils
  TITLE:=Ninux NG Firmware
  MAINTAINER:=contatt@ninux.org
  DEPENDS:=+olsrd-ninux-all +iw +nowolfsplash +tind +kmod-ipv6
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

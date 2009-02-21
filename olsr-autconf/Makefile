# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 600 2009-02-13 23:15:47Z oraziopiratadellospazio $

include $(TOPDIR)/rules.mk

PKG_NAME:=olsr-autoconf
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install



include $(INCLUDE_DIR)/package.mk

define Package/olsr-autoconf
  SUBMENU:=LUA
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Olsr Autoconf 
  URL:=http://www.ninux.org
  DEPENDS:=at
endef

define Package/olsr-autoconf/description
  TODO
endef



define Build/Configure
endef


define Build/Compile
endef


define Package/olsr-autoconf/install
	$(INSTALL_DATA) files/olsrd.conf $(1)/etc/
	$(INSTALL_DATA) files/olsrd $(1)/etc/init.d/
endef

$(eval $(call BuildPackage,olsr-autoconf))

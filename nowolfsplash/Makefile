# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 600 2009-02-13 23:15:47Z oraziopiratadellospazio $

include $(TOPDIR)/rules.mk

PKG_NAME:=nowolfsplash
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install
LUAC = luac
LUAC_OPTIONS = -s
LUA_TARGET ?= source

LUA_MODULEDIR = /usr/lib/lua
LUA_LIBRARYDIR = /usr/lib/lua

LUCI_MODULEDIR = $(LUA_MODULEDIR)/luci
LUCI_LIBRARYDIR = $(LUA_LIBRARYDIR)/luci

HTDOCS = /www

include $(INCLUDE_DIR)/package.mk

define Package/nowolfsplash
  SUBMENU:=LUA
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Ninux splash 
  URL:=http://www.ninux.org
  DEPENDS:=at
endef

define Package/nowolfsplash/description
  TODO
endef



define Build/Configure
endef


define Build/Compile
endef


define Package/nowolfsplash/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DIR) $(1)/$(LUA_MODULEDIR)
	$(INSTALL_DIR) $(1)/$(LUCI_MODULEDIR)
	$(INSTALL_DIR) $(1)/$(HTDOCS)
	cp -rf root/* $(1)/
	cp -rf luasrc/* $(1)/$(LUCI_MODULEDIR)
#	cp -rf htdocs/* $(1)/$(HTDOCS)
endef

$(eval $(call BuildPackage,nowolfsplash))

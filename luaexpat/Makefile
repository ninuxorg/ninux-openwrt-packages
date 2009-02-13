# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=luaexpat
PKG_VERSION:=1.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://luaforge.net/frs/download.php/2469/ 
PKG_MD5SUM:=6ecb895ccf5cff1e7f2facd438b1f8d0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/luaexpat
  SUBMENU:=LUA
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=LUAexpat 
  URL:=http://www.keplerproject.org/luaexpat/
  DEPENDS:=lua +libexpat
endef

define Package/luaexpat/description
  TODO
endef



define Build/Configure
endef


define Build/Compile
	cp -rf files/compat-5.1r5 $(PKG_BUILD_DIR)/compat-5.1r5
	$(MAKE) -C $(PKG_BUILD_DIR) \
	EXPAT_INC="$(STAGING_DIR)/usr/include/" \
	LUA_INC="$(STAGING_DIR)/usr/include/" \
	LUA_LIBDIR="$(STAGING_DIR)/usr/lib/" \
	COMPAT_DIR="$(PKG_BUILD_DIR)/compat-5.1r5" \
	LIB_OPTION="-shared -L$(STAGING_DIR)/usr/lib/" \
	CC="$(TARGET_CROSS)gcc" \
	LD="$(TARGET_CROSS)ld -shared" 
endef


define Package/luaexpat/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/lxp.so.1.1.0 $(1)/usr/lib/lua/lxp.so
	$(INSTALL_DIR) $(1)/usr/lib/lua/lxp
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/lxp/lom.lua $(1)/usr/lib/lua/lxp
endef

$(eval $(call BuildPackage,luaexpat))

# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 12696 2008-09-25 12:15:32Z cyrus $

include $(TOPDIR)/rules.mk

PKG_NAME:=luasec
PKG_VERSION:=0.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://luaforge.net/frs/download.php/3920/ 
PKG_MD5SUM:=a88f2c05d22abfcc9ab92bd1d6f32b37

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/luasec
  SUBMENU:=LUA
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=LUASec 
  URL:=http://luasec.luaforge.net/
  DEPENDS:=lua +openssl +luasocket
endef

define Package/luasec/description
  LuaSec is a binding for OpenSSL library to provide TLS/SSL communication.
endef



define Build/Configure
endef


define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src linux \
	INCDIR="-I$(STAGING_DIR)/usr/include/" \
	LIBDIR="-L$(STAGING_DIR)/usr/lib/" \
	CC="$(TARGET_CROSS)gcc" \
	LD="$(TARGET_CROSS)ld -shared" 
endef


define Package/luasec/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/{ssl.so,ssl.lua} $(1)/usr/lib/lua
endef

$(eval $(call BuildPackage,luasec))

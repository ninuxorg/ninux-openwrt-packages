#
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=prosody
PKG_VERSION:=0.5.2-beta
PKG_RELEASE:=0

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://prosody.im/downloads/source/
PKG_MD5SUM:=09a84095a1bd5f410fcef52da2026a49

include $(INCLUDE_DIR)/package.mk

define Package/prosody
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+liblua +libidn
  TITLE:=XMPP server
  URL:=http://prosody.im
endef

define Package/prosody/description
  Prosody is an exciting new server for Jabber/XMPP
  written in Lua. It aims to be easy to use, and light
  on resources
endef

define Package/prosody/conffiles
/etc/prosody/prosody.cfg.lua
endef

define Build/Configure
	(cd $(PKG_BUILD_DIR); ./configure \
		--prefix=/usr \
		--with-lua="$(STAGING_DIR)/host/bin" \
		--with-lua-include="$(STAGING_DIR)/usr/include/" \
		--with-lua-lib="$(STAGING_DIR)/usr/lib" \
		--datadir="/etc/prosody/data" \
		--cflags="$(TARGET_CFLAGS)" \
	)
endef

define Build/Compile
	$(call Build/Compile/Default,\
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		PREFIX="/usr" \
		MAKE="make LIB_DIR=$(STAGING_DIR)/usr/lib" \
		all install \
	)
endef

define Package/prosody/install
	$(INSTALL_DIR) $(1)/
	$(INSTALL_DIR) $(1)/etc/prosody/data
	$(CP) $(PKG_INSTALL_DIR)/* $(1)/
	$(CP) files/root/ $(1)/
endef

$(eval $(call BuildPackage,prosody))

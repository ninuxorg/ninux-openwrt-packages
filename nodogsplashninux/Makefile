#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nodogsplashninux
PKG_VERSION:=0.9_beta9.9.6
PKG_RELEASE:=2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/ninuxorg/nodogsplashninux.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_FIXUP:=autoreconf
PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/nodogsplashninux
  SUBMENU:=Captive Portals
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpthread +iptables-mod-ipopt
  TITLE:=Ninux NoDogSplash
  URL:=https://github.com/ninuxorg/nodogsplashninux
endef

define Package/nodogsplashninux/description
	Nodogsplash offers a simple way to open a free hotspot providing restricted access to an
	internet connection. It is intended for use on wireless access points running OpenWRT
	(but may also work on other Linux-based devices).
endef

define Build/Configure
	$(call Build/Configure/Default,\
		--enable-static \
		--enable-shared \
	)
endef

define Build/Compile
	$(call Build/Compile/Default, \
		mkinstalldirs="$(INSTALL_DIR)")
endef

define Build/Install
	mkdir -p $(PKG_INSTALL_DIR)/usr/{share{,/doc/nodogsplash-$(PKG_VERSION)},lib,include{,/nodogsplash},bin,sbin}/
	$(call Build/Install/Default, \
		mkinstalldirs="$(INSTALL_DIR)" \
		install)
endef

define Package/nodogsplashninux/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc/nodogsplash
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/nodogsplash.conf $(1)/etc/nodogsplash/
	$(SED) 's,br0,br-lan,' $(1)/etc/nodogsplash/nodogsplash.conf
	$(CP) $(PKG_BUILD_DIR)/htdocs $(1)/etc/nodogsplash/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nodogsplash.init $(1)/etc/init.d/nodogsplash
	$(SED) 's,\(do_module_tests "imq"\),#\1,' $(1)/etc/init.d/nodogsplash
	$(SED) 's,\(do_module_tests "ipt_IMQ"\),#\1,' $(1)/etc/init.d/nodogsplash
	$(SED) 's,\(do_module_tests "sch_htb"\),#\1,' $(1)/etc/init.d/nodogsplash
endef

define Package/nodogsplashninux/conffiles
/etc/nodogsplash/nodogsplash.conf
endef

$(eval $(call BuildPackage,nodogsplashninux))

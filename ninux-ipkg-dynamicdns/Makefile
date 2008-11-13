# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-dynamicdns
PKG_VERSION:=0.1
PKG_RELEASE:=alpha

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-dynamicdns
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+netcat
  TITLE:=Ninux.org's dynamic DNS client 
endef

define Package/ninux-dynamicdns/install
	$(CP) -a ./files/* $(1)/
#	$(CP) -a ./ipkg/ninux-dynamicdns.postinst $(1)/CONTROL/postinst
#	$(CP) -a ./ipkg/ninux-dynamicdns.prerm $(1)/CONTROL/prerm
endef

define Package/ninux-dynamicdns/description
	ninux.org's dynamic DNS client http://wiki.ninux.org/DnsDinamico
endef

define Build/Compile
endef

$(eval $(call BuildPackage,ninux-dynamicdns))


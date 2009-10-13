# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-adm5120
PKG_VERSION:=0.1
PKG_RELEASE:=beta

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-adm5120
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+webif +webif-lang-it +olsrd-ninux +ip +libpthread  +horst +snmpd +tcpdump @TARGET_adm5120
  TITLE:=Ninux.org Community Config Package
endef

define Package/ninux-amd5120/install
	$(CP) -a ./files/* $(1)/
endef

define Package/ninux-adm5120/description
  Prepara il router per la rete ninux.org 
endef

define Build/Compile
endef

$(eval $(call BuildPackage,ninux-adm5120))


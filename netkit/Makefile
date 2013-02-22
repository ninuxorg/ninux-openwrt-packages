# 
# Copyright (C) 2009 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=netkit
PKG_VERSION:=0.1
PKG_RELEASE:=beta

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/netkit
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+kmod-ipv6 +kmod-fs-ext3 @TARGET_uml
  TITLE:=Netkit Package
endef

define Build/Compile
endef

define Package/netkit/install
	$(CP) -a ./files/* $(1)/
endef

define Package/netkit/description
  Description of Netkit Package
endef


$(eval $(call BuildPackage,netkit))


# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-webiftheme
PKG_VERSION:=8.01
PKG_RELEASE:=2

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-webiftheme
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+webif 
  TITLE:=Ninux.org Community Webif Theme Package
  PKGARCH:=all
endef

define Package/ninux-webiftheme/install
	$(CP) -a ./files/* $(1)/
	$(CP) -a ./ipkg/ninux-webiftheme.postinst $(1)/CONTROL/postinst
	$(CP) -a ./ipkg/ninux-webiftheme.prerm $(1)/CONTROL/prerm
endef

define Package/ninux-webiftheme/description
  ninux.org's web interface theme
endef

define Build/Compile
endef

$(eval $(call BuildPackage,ninux-webiftheme))


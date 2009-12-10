# 
# Copyright (C) 2009 Claudio Mignanti
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=strong-anonymous-router
PKG_VERSION:=3

include $(INCLUDE_DIR)/package.mk

define Package/sar
  SECTION:=utils
  TITLE:=Strong Anonymous Router
  MAINTAINER:=Claudio Mignanti <c.mignanti@gmail.com>
  DEPENDS:=+kmod-ipsec +kmod-ipsec4 +tor +privoxy +ipsec-tools +stunnel +php4 +php4-cgi +olsrd
endef

define Package/sar/description
   Strong Anonymous Router - meta package
endef

define Build/Compile
endef

define Package/sar/install
	$(INSTALL_DIR) $(1)/
	$(CP) -r ./files/* $(1)/
endef

$(eval $(call BuildPackage,sar))

#
# Copyright (C) 2010-2012  Gioacchino Mazzurco <gmazzurco89@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <http://www.gnu.org/licenses/>.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=reghack
PKG_VERSION:=1
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package.mk


define Package/$(PKG_NAME)
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Regulatory domain unlocker
endef

define Package/$(PKG_NAME)/install
	@mkdir -p $(1)/usr/bin
	$(CP)  $(PKG_BUILD_DIR)/reghack $(1)/usr/bin/reghack
	@chmod +x $(1)/usr/bin/reghack
	@mkdir -p $(1)/etc/uci-defaults
	$(CP) src/reghack.sh $(1)/etc/uci-defaults/reghack.sh
	@chmod +x $(1)/etc/uci-defaults/reghack.sh
endef

define Build/Compile
	$(TARGET_CC) src/reghack.c -o  $(PKG_BUILD_DIR)/reghack
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

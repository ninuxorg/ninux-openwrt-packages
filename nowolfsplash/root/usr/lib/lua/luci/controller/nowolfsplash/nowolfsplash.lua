module("luci.controller.nowolfsplash.nowolfsplash", package.seeall)

function index()
    entry({"nowolfsplash"}, call("show_agreement"), "Click here", 10).dependent=false
end
 
function show_agreement()
    local remote_addr = luci.sys.getenv("REMOTE_ADDR") 
    local mac = luci.sys.net.ip4mac(luci.http.getenv("REMOTE_ADDR")) or "" 
    local isAccepted = luci.http.formvalue ("submit")  	
    if isAccepted then
    	require("os")
	os.execute("iptables -t nat -I PREROUTING -m mac --mac-source " ..mac.. " -j ACCEPT")
    	luci.template.render("nowolfsplash/welcome", {})
    else
    	luci.template.render("nowolfsplash/splash", {}) 
    end
end

        

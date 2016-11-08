local cjson = require "cjson"
local target_sock_name = "/tmp/GTS.sock"

local function send_unix_req(request)
    local socket = require("socket")
    socket.unix = require("socket.unix")
    local client = socket.unix.udp()
    local clt_socket_name = "/tmp/gts_api.sock"
    client:bind(clt_socket_name)
    client:settimeout(10) -- wait message 10 seconds

    client:sendto(request, target_sock_name)
    local msg, addr = client:receivefrom()

    client:close()
    os.execute('rm '..clt_socket_name)
    if not msg then
        msg = '{"status":"failed","err_msg":"action failed, pleaser try again"}'
    end
    local res = cjson.decode(msg)
    return res
end

local act = arg[1]
local token = arg[2]
local cmd = {}

if act == "add" then
    cmd.act = "add_user"
    cmd.password = "geewantest"
    cmd.txquota = 10240000
    cmd.expire = "2017/6/3 14:57:00"
elseif act == "del" then
    cmd.act = "del_user"
    cmd.token = token
end
local request = cjson.encode(cmd)
local rsp = send_unix_req(request)
print(rsp)

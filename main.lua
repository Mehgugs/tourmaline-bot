local T = require "framework"
local discordia = require  "discordia"
local Logger = discordia.Logger(3, "!%F %T")
      Logger:log(3, "Initializing Tourmaline")

local reql = require"luvit-reql"
      
T(function(client)
    local fs = require"fs"
    local TOKEN = "Bot " .. assert(fs.readFileSync("./TOKEN"))
    local ready_timer = discordia.Stopwatch()
    discordia.storage.reqlconnection = reql.connect{
        address = "127.0.0.1",
        port = 28015,
        file = 'luvitreql.log',
        reconnect = true,
        user = 'admin',
        password = '',
        reusable = false,
        debug = false
    }
    client:on('ready', function() 
        ready_timer:stop()
        Logger:log(3, "%s ready, took %s", client.user.name, ready_timer:getTime():toString())
    end)
    ready_timer:start()
    return TOKEN
end)



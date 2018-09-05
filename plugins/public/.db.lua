local discordia = require"discordia"
local T = require"framework"
local reql = require"luvit-reql"
local util = T.util

local function reql_safe(s) return s:gsub("[^%w_]", "_") end

plugin:on('loaded', function(self) 
    if self.connection == nil then
        self:info"Linking with reql connection..." 
        self.dbname = reql_safe(self.rawname)
        self.connection = assert(discordia.storage.reqlconnection)
        self:info"Connection OK"
        self:info"Defining shortcuts"
        function self:reql() return self.connection.reql() end 
        function self:db() return self.connection.reql().db(self.dbname) end
        --check and create `core` database
        self:info"Checking for databases..."
        local ret = self:reql().dbList().run()
        self:info"Got databases."
        if not util.contains(ret[1], self.dbname) then
            self:info"Creating database"
            self:reql().dbCreate(self.dbname).run()
            self:info('Created new reql database %q', self.dbname)
        end
        self:info('Linked to reql database %q', self.dbname)
    end
    local cfg = self:config()
    self:unloadableSource(cfg.controller)
end)
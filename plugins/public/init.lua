local discordia = require"discordia"
plugin:unloadableSource('.db')

plugin.localtime = plugin.localtime or discordia.Stopwatch()

plugin:on('reloaded', function(self) 
    self.localtime:reset()
    discordia.storage.config[self.rawname] = nil
    self:config() 
end)
plugin:on('loaded', function(self) self.localtime:start() end)
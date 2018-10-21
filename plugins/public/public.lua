local discordia = require"discordia"
local T = require"framework"
local pp = require"pretty-print"
local b64decode = require"base64".decode
local base64 = require"openssl".base64
local http = require"coro-http"
local fs = require"fs"
local lpeg = require"lpeg"
lpeg.locale(lpeg)
local Github = plugin:unloadableSource("gh/github")

local util = T.util
local Embed = T.Embed
local Group = T.Command.Group()
local syntax = T.syntax
local insert, concat, pack, unpack, sort = table.insert, table.concat, table.pack, table.unpack, table.sort
local dump = pp.dump
local wrap = coroutine.wrap

local Date, Time = discordia.Date, discordia.Time

local function tasks(...)
    for _, t in ipairs{...} do 
        t()
    end
end

discordia.extensions.string()

discordia.storage.config[plugin.rawname] = nil --reset our config
local cfg = plugin:config()

local arithmetic = plugin:unloadableSource('arith2')

plugin.whitelist = plugin.whitelist or {}
plugin.userblacklist = plugin.userblacklist or {}

if plugin.tables == nil then 
    plugin:info"Getting tables"
    local tables = plugin:db().tableList().run()
    plugin.tables = tables
    plugin:info("Got Tables")
    if not util.contains(tables[1], "whitelist") then 
        plugin:db().tableCreate('whitelist').run()
        plugin:info('Created table "whitelist" in database %q.', plugin.dbname)
    end
    if not util.contains(tables[1], "userblacklist") then 
        plugin:db().tableCreate('userblacklist').run()
        plugin:info('Created table "userblacklist" in database %q.', plugin.dbname)
    end
end

local owner = function(_, msg) return msg.author.id == msg.client.owner.id end
local function get_whitelist_document(plugin, id)
    if plugin.whitelist[id] ~= nil then 
        return plugin.whitelist[id]
    else 
        local ret = plugin:db().table('whitelist').get(id).run()
        plugin.whitelist[id] = ret 
        return plugin.whitelist[id]
    end
end

local function get_userblacklist_document(plugin, id)
    if plugin.userblacklist[id] ~= nil then 
        return plugin.userblacklist[id]
    else 
        local ret, err = plugin:db().table('userblacklist').get(id).run()
        plugin.userblacklist[id] = ret
        return plugin.userblacklist[id]
    end
end

local function whitelist_document(id, rule)
    return {
        id = id, 
        rule = not not rule 
    }
end

local function userblacklist_document(id)
    return {
        id = id
    }
end

local function add_document(D, tbl)
    plugin:db().table(tbl).inOrUp(D).run()
end

local function pop_document(id, tbl)
    return plugin:db().table(tbl).get(id).delete().run()
end

--predicates

local function inWhitelistedChannel(cmd, msg) 
    local plg = cmd.plugin
    local d = get_whitelist_document(plg, msg.channel.id)
    return d and d.rule
end

local function isUserOK(cmd, msg)
    local plg = cmd.plugin
    local d = get_userblacklist_document(plg, msg.author.id)
    return not d
end

local function hasRequiredpermissions(cmd, msg)
    local me = msg.guild.me
    if me then 
        local perms = me:getPermissions(msg.channel)
        local res = perms:has(unpack(cmd.requiredPermissions or {}))
        if not res and perms:has("sendMessages") then
            msg:reply(":warning: I do not have all of the required permissions to run that command.")
        end
        return res 
    end
end

local function argPredicate(cmd)
    cmd.argument_predicate = cmd.argument_predicate or #cmd.parser*lpeg.Cc(true)
    return cmd.argument_predicate
end

local function capture_error(f, ...)
    local s, e  = pcall(f, ...)
    return not s and e or nil
end

local function hasContent(cmd, msg) 
    local info = T.Command.find(msg.content)
    local pred = argPredicate(cmd)
    local v =  info.args and pred:match(info.args)
    if not v then 
        local r = capture_error(cmd.raiseArgError, cmd)
        msg:reply{embed = r.response}
    end
    return v
end

local function call_command(msg, content)
    local info = T.Command.find(content:trim())
    if info then
        local cmd = Group:resolve(info.command)

        if cmd and info.args then 
            local success, ret = pcall(cmd.body,cmd,msg,cmd.parser:match(info.args))
            if not success then 
                cmd:replyWithErr(msg, ret)
            elseif success and ret ~= nil then
                msg:reply(ret) 
            end
        end
    end
end

local function call_command_args(msg, content, ...)
    local info = T.Command.find(content:trim())
    if info then
        local cmd = Group:resolve(info.command)

        if cmd and info.args then 
            local success, ret = pcall(cmd.body,cmd,msg,...)
            if not success then 
                cmd:replyWithErr(msg, ret)
            elseif success and ret ~= nil then
                msg:reply(ret) 
            end
        end
    end
end

-- commands open to the public --

local PublicCommand = T.Command:extend{
    prefix = "->",
    plugin = plugin,
    src = plugin:src(),
    scope = "admin",
    __pipes = false,
    conds = {
        predicates = { --predicates are executed in order
            util.guild_only,
            hasRequiredpermissions,
            isUserOK,
            inWhitelistedChannel
        }
    },
    group = Group, --the command group which contains the commands
    __dmerr = false,
}

-- in example of 

local mention_parser = syntax.some(
    syntax.anywhere(
        syntax.animoji_mention + syntax.emoji_mention 
    )
)

local insert, sort = table.insert, table.sort

local function command_steal(cmd, msg, arg)
    
    if not arg then cmd:raiseArgError() end
    local messages = msg.channel:getMessages(50)

    arg = arg:lower()

    local subs = {}
    local other = {}

    for message in messages:iter() do
        local emojis = mention_parser:match(message.content) or {}
        for i, e in ipairs(emojis) do
            if e.name:lower():find(arg, 1, true) then
                insert(subs, e)
            else
                insert(other,e)
            end
        end
    end

    local function levensort(a, b)
        return a.name:levenshtein(arg) < b.name:levenshtein(arg)
    end

    local emoji
    if subs[1] then
        sort(subs, levensort)
        emoji = subs[1]
    elseif other[1] then
        sort(other, levensort)
        emoji = other[1]
    end

    if emoji then
        local guild = msg.client:getGuild('298412191906791425')
        if guild then
            local ext = emoji.type == 'animoji' and 'gif' or 'png'
            local res, data = http.request('GET', "https://cdn.discordapp.com/emojis/%s.%s" % {emoji.id, ext})
            if res.code == 200 then
                local encoded = 'data:;base64,' .. base64(data)
                emoji = guild:createEmoji(emoji.name, encoded)
                if emoji then
                    return ("Emoji %s stolen!" % emoji.mentionString)
                end
            end
        end
    end
end

local function printLine(...)
	local ret = {}
	for i = 1, select('#', ...) do
		insert(ret, tostring(select(i, ...)))
	end
	return concat(ret, '\t')
end

local function prettyLine(...)
	local ret = {}
	for i = 1, select('#', ...) do
		insert(ret, dump(select(i, ...), nil, true))
	end
	return concat(ret, '\t')
end

local meta = {__index = _G}

function command_eval(cmd, msg, arg)
    if not arg or arg.language ~= 'lua' or arg.code == '' or arg.code == nil then 
        cmd:raiseArgError()
    end
    arg = arg.code
    local lines = {}
    local sandbox = setmetatable({}, meta)
    sandbox.msg = msg
    sandbox.require = require
    sandbox.channel = msg.channel
    sandbox.guild = msg.guild
    sandbox.client = msg.client
    sandbox.plugin = cmd.plugin
    sandbox.discordia = discordia
    sandbox.cmd = cmd
    sandbox.T = T
    sandbox.print = function(...) insert(lines, printLine(...)) end
    sandbox.p = function(...) insert(lines, prettyLine(...)) end

    local fn, err = load(arg, cmd.name, 't', sandbox)
    if not fn then error{
        response = #Embed{
            title = "Failed to compile function",
            description = err:codeblock(),
            color = 0xFF4A32
        },
        dm = false,
    } end

    wrap(function()
        local ret = pack(pcall(fn))
        local s, res = ret[1], {n = ret.n - 1; unpack(ret, 2, ret.n)}
        if not s then error{
            response = #Embed{
                title = "Failed to execute function",
                description = res[1]:codeblock(),
                color = 0xFF4A32
            },
            dm = false,
        } end
        if res.n > 0 then
            for i = 1, res.n do
                res[i] = tostring(res[i])
            end
            insert(lines, concat(res, '\t'))
        end
        if #lines > 0 then 
            msg:reply( concat(lines, '\n'):lang('lua') )
        else
            msg:addReaction('👍')
        end
    end)()
end

local NaN = (-1)^.5
local function command_math(cmd, msg, result)
    if result then 
        result = result == NaN and "NaN" or result 
        return "Result: %s" % tostring(result):codeblock()
    else 
        return "Syntax Error!"
    end
end

local function command_source(_, msg, content)
    if content then 
        local cinfo = T.Command.find(content:trim())
        local cmd = Group:resolve(cinfo.command)
        if cmd then
            local info = debug.getinfo(cmd.body)
            if info.what == 'Lua' then
                fs.readFile(info.source:sub(2), T.here())
                local err, content = coroutine.yield()
                if not err then 
                    local lines = content:split('\n')
                    local func = {}
                    for i = info.linedefined, info.lastlinedefined do 
                        table.insert(func, lines[i])
                    end
                    local data = table.concat(func, '\n')
                    if info.nups > 0 then 
                        msg:reply("This function depends on upvalues in it's enclosing scope.")
                    end
                    if #lines <= 15 then 
                        return data:lang('lua')
                    else
                        return {file = {cmd.name .. ".lua", data}}
                    end
                else
                    return "Error locating function!"
                end
            end
        end
    end
end

local function searchMember(members, arg)

	local member = members:get(arg)
	if member then return member end

	local distance = math.huge
	local lowered = arg:lower()

	for m in members:iter() do
		if m.nickname and m.nickname:lower():find(lowered, 1, true) then
			local d = m.nickname:levenshtein(arg)
			if d == 0 then
				return m
			elseif d < distance then
				member = m
				distance = d
			end
		end
		if m.username:lower():find(lowered, 1, true) then
			local d = m.username:levenshtein(arg)
			if d == 0 then
				return m
			elseif d < distance then
				member = m
				distance = d
			end
		end
	end

	return member

end

local whois_parser = ((syntax.nick_mention+syntax.user_mention)/function(i) return i.id end) + syntax.everything
local upper = string.upper
local function command_whois(cmd, msg, content)
    local m = content and searchMember(msg.guild.members, content:trim()) or  msg.guild:getMember(msg.author)
        
    local color = m:getColor().value 
    local embed = Embed()
        :description("User info for %s" % m.user.tag:sanitize())
        :thumbnail{url = m.user:getAvatarURL()} 
        :field{name = "Name"; value = m.nickname and ('%s (%s)' % {m.username:sanitize(), m.nickname:sanitize()}) or m.username}
        :field{name = "ID"; value = m.id}
        :field{name = 'Status', value = m.status:gsub('^%l', upper)}
    local joined_discord = Date.fromSnowflake(m.id)
    embed:field{
        name = 'Joined Discord', 
        value = joined_discord:toString()
        .."\nwhich was %s ago." % Time.fromSeconds((Date() - joined_discord):toSeconds()):toString()
    }
    if m.joinedAt then 
        local joined = Date.fromISO(m.joinedAt)
        embed:field{
            name = "Joined %s" % msg.guild.name; 
            value = joined:toString() 
            .."\nwhich was %s ago." % Time.fromSeconds((Date() - joined):toSeconds()):toString()
        }
    else 
        embed:field{
            name = "Joined %s" % msg.guild.name; 
            value = "??"
        }  
    end
    return {embed = #embed}
    
end

local function command_avatar(cmd, msg, content)
    local m = content and searchMember(msg.guild.members, content:trim()) or msg.guild:getMember(msg.author)
    return {embed = #Embed{image = {url = m.user:getAvatarURL()}}}
end

local function command_ginfo(cmd, msg)
    local guild = msg.guild
	local owner = guild.owner
    local now = Date()
    local createdAt = Date.fromSnowflake(guild.id)
    if owner == nil then
        owner = msg.client:getUser(guild.ownerId)
    end
	return {
		embed = #Embed{
			thumbnail = guild.iconURL and {url = guild.iconURL} or nil,
			fields = {
				{name = 'Name', value = guild.name, inline = true},
				{name = 'ID', value = guild.id, inline = true},
				{name = 'Owner', value = owner.tag, inline = true},
                {name = 'Created', value = createdAt:toString()
                .."\nwhich was %s ago." % Time.fromSeconds((now - createdAt):toSeconds()):toString(), inline = true},
				{name = 'Members', value = guild.members:count(isOnline) .. ' / ' .. guild.totalMemberCount, inline = true},
				{name = 'Categories', value = tostring(#guild.categories), inline = true},
				{name = 'Text Channels', value = tostring(#guild.textChannels), inline = true},
				{name = 'Voice Channels', value = tostring(#guild.voiceChannels), inline = true},
				{name = 'Roles', value = tostring(#guild.roles), inline = true},
				{name = 'Emojis', value = tostring(#guild.emojis), inline = true},
			}
		}
    }
end
local gh = Github(cfg["github-token"], "<your account here>")

local function exactly(n, p) 
    local patt = lpeg.P(p)
    local out = patt
    for i = 1, n-1 do 
        out = out * patt
    end
    return out
end

local token = syntax.some(
    syntax.anywhere(lpeg.C("M" * exactly(58, lpeg.R("09", "az", "AZ") + "_" + ".")))
)
local function command_tokenfind(cmd, msg, lang)
    local success, resp, reason = gh:search_code("discord Mz", lang and lang:trim())
    local count = 0
    local urls = {}
    msg.channel:broadcastTyping()
    if success then 
        for _, item in ipairs(resp.items) do 
            local resource_url = item.url
            local success, data = gh:request(resource_url, "GET")
            if success then 
                local content = b64decode(data.content:gsub("\n", ""))
                local tokens = token:match(content) 
                if tokens and #tokens > 0 then 
                    count = count + #tokens 
                    insert(urls, item.repository.html_url)
                end
            else 
                return "Failed to load file content! %s" % (res and res.reason)
            end
        end
        return {
            content = "I found %d tokens in public repositories" %  count;
            file = {"repos.txt", concat(urls,"\n")}
        }
    else
        return "Http error: %s %s" % {resp, reason}
    end
end

-- decode a two-byte UTF-8 sequence
local function f2 (s)
    local c1, c2 = string.byte(s, 1, 2)
    return c1 * 64 + c2 - 12416
end
  
-- decode a three-byte UTF-8 sequence
local function f3 (s)
    local c1, c2, c3 = string.byte(s, 1, 3)
    return (c1 * 64 + c2) * 64 + c3 - 925824
end
  
-- decode a four-byte UTF-8 sequence
local function f4 (s)
    local c1, c2, c3, c4 = string.byte(s, 1, 4)
    return ((c1 * 64 + c2) * 64 + c3) * 64 + c4 - 63447168
end
  
local cont = lpeg.R("\128\191")   -- continuation byte
  
local utf8_pattern = lpeg.R("\0\127") / string.byte
           + lpeg.R("\194\223") * cont / f2
           + lpeg.R("\224\239") * cont * cont / f3
           + lpeg.R("\240\244") * cont * cont * cont / f4
  
local decode_pattern = lpeg.Ct(utf8_pattern^0) * -1

local utf8 = function(text) return ipairs(decode_pattern:match(text) or {}) end

local function utf8char(unicode)
	if unicode <= 0x7F then return string.char(unicode) end

	if (unicode <= 0x7FF) then
		local Byte0 = 0xC0 + math.floor(unicode / 0x40);
		local Byte1 = 0x80 + (unicode % 0x40);
		return string.char(Byte0, Byte1);
	end;

	if (unicode <= 0xFFFF) then
		local Byte0 = 0xE0 +  math.floor(unicode / 0x1000);
		local Byte1 = 0x80 + (math.floor(unicode / 0x40) % 0x40);
		local Byte2 = 0x80 + (unicode % 0x40);
		return string.char(Byte0, Byte1, Byte2);
	end;

	if (unicode <= 0x10FFFF) then
		local code = unicode
		local Byte3= 0x80 + (code % 0x40);
		code       = math.floor(code / 0x40)
		local Byte2= 0x80 + (code % 0x40);
		code       = math.floor(code / 0x40)
		local Byte1= 0x80 + (code % 0x40);
		code       = math.floor(code / 0x40)
		local Byte0= 0xF0 + code;

		return string.char(Byte0, Byte1, Byte2, Byte3);
	end;

	error 'Unicode cannot be greater than U+10FFFF!'
end

local function shift(block, start, stop, text)
    local out = {}
    local offset = block - start
    for _, c in utf8(text) do
        if c >= start and c <= stop then c = c + offset end
        table.insert(out,utf8char(c))
    end
    return table.concat(out)
end

local function bind1(f, v) return function(...) return f(v, ...) end end

local function bind(f, ...) for _, arg in ipairs{...} do f = bind1(f, arg) end return f end

local fwr = bind(shift, 0xFF01, 0x21, 0x7E)

local full_width = function(text) fwr(text):gsub('%s', "  ") end

local fucking_emoji = bind(shift, 0x1F300, 0x21, 0x7E)

local function command_fullwidth(_, _, content)
    return content and fwr(content:gsub(" ", "  "))
end

local function command_emoji(_, _, content)
    return content and fucking_emoji(content)
end

local tohex = function(n) return tonumber(n, 16) end

local numeral = lpeg.C(lpeg.digit^1)/tonumber 
local hex = lpeg.P("0x")*lpeg.C(lpeg.R("09", "AF", "af")^1)/tohex

local shift_parser = (hex + numeral) * syntax.everything
 
local function command_blockShift(cmd, _, block, content)
    if not (block and content) then cmd:raiseArgError() end
    assert(block > 0 and block <= 0xE0100, "Block too large for a meaningful shift.")
    return shift(block, 0x21, 0x7E, content and content or '')
end

--discordia doc provider --

local doc_parser = plugin:unloadableSource('discordia-docs/parser')

plugin.docs = plugin.docs or {}
plugin.embeds = plugin.embeds or {overview = {}; properties = {}; methods = {}}
local register_doc_commands
local class_path = plugin:path("discordia-docs/classes/")
local function index_classes() --load and parse all class files into plugin.docs
    plugin.classes = {}
    fs.scandir(class_path,T.here())
    local err, directory = coroutine.yield() 
    if err then 
        plugin:error(err)
        return
    end
    for file, type in directory do 
        if type == 'file' then 
            local full = plugin:path(class_path, file)
            fs.readFile(full, T.here())
            local err, content = coroutine.yield()
            if err then 
                plugin:error(err)
                return
            end 
            local k = file:prefix(".md")
            local docs = doc_parser:match(content)
            plugin.docs[k] = docs
            docs.methods = docs.methods or {}
            docs.properties = docs.properties or {}
            if docs.static_methods then 
                for k, v in pairs(docs.static_methods) do 
                    v.static = true
                    docs.methods[k] = v
                end
            end
            if docs.inherited_methods then 
                for super, data in pairs(docs.inherited_methods) do 
                    for name, m in pairs(data.methods) do 
                        m.superclass = data.class
                        docs.methods[name] = m 
                    end
                end
            end
            if docs.inherited_properties then 
                for super, props in pairs(docs.inherited_properties) do 
                    for name, m in pairs(props.properties) do 
                        m.superclass = props.class
                        docs.properties[name] = m 
                    end
                end
            end
            docs.link = "https://github.com/SinisterRectus/Discordia/wiki/%s" % k
        end
    end
end

local function grep(name, from)
    name = name:lower()
    local guessed;
    local dist = math.huge 
    for k in pairs(from) do 
        if k:lower():find(name, 1, true) then 
            local l = k:levenshtein(name)
            if l == 0 then return k end
            if l < dist then 
                dist = l 
                guessed = k
            end
        end
    end
    return guessed
end

local function grep_class(class) return grep(class, plugin.docs) end

local reference = lpeg.P"[[" * lpeg.C((1 - lpeg.P"]]")^1) * "]]" 
local refs = {}

local function resolve_references(s)
    return lpeg.gsub(s, reference, function(s) 
        return ("[%s](%s)") % {s, plugin.docs[s] and plugin.docs[s].link or ''} 
    end)
end

local function strip_references(s)
    return lpeg.gsub(s, reference, "%1")
end

local function strip_stuff(s)
    return lpeg.gsub(s, "*Instances of this class should not be constructed by users.*", "")
end

local function superclassToTitle(s)
    return "[%s](%s)" % {s, plugin.docs[s] and plugin.docs[s].link or ''}
end

local function add_types(acc, _, name, types)
    if types[name] and types[name][2] then 
        insert( acc,  "optional %s %s" % {types[name][1], name} )   
    elseif types[name] and not types[name][2] then 
        insert(acc, "%s %s" % {types[name][1], name})
    else 
        insert(acc, "? %s" % name)
    end
    return acc
end

local function interlace_types(list, types)
    return concat(util.foldWithArgs(list, add_types, {}, types), ", ")
end

local function display_arguments(pre, list, types, resolve)
    local string
    if types and type(types) == 'table' then
        string = interlace_types(list, types)
    else 
        string = concat(list, ", ") 
    end
    if resolve then 
        return "%s(%s)" % {pre, resolve_references( string )}
    else 
        return "%s(%s)" % {pre, strip_references( string )}
    end
end

local function generate_overview(name)
    local docs = plugin.docs[name]
    if docs then 
        local embed = Embed()
        if docs.class then 
            embed:title(
                "Overview for %s" % display_arguments(docs.class, docs.constructor, docs.constructor_arguments, false)  
            )
        else 
            embed:title(
                "Overview for %s()" % name
            )
            embed:textfooter("Instances of this class should not be constructed by users.")
        end
        embed:url(docs.link)
        if docs.superclasses then 
            embed:field{name = "Extends"; value = concat(util.map(docs.superclasses, superclassToTitle), ", ")}
        end
        embed:description(resolve_references(strip_stuff(docs.description)))
        plugin.embeds.overview[name] = {#embed}
    end 
end

local function embedandreply (msg,e) msg:reply{embed = e} return msg end

local function add_property_to_embed(embed, name, prop_name, prop)
    embed:field{name = "%s.%s" % {name, prop_name}; value = ("Type : %s\n" % resolve_references( prop.type ))
    ..resolve_references(prop.desc)}
end

local function alphabetize(i,j) return i:lower() < j:lower() end
local function generate_properties(name)
    local docs = plugin.docs[name]
    if docs then 
        local embeds = {}
        plugin.embeds.properties[name] = embeds
        local tembed = Embed()
        if docs.class then 
            tembed:title(
                "Properties of %s" % display_arguments(docs.class, docs.constructor, nil, false)    
            )
        else 
            tembed:title(
                "Properties of %s()" % name
            )
            tembed:textfooter("Instances of this class should not be constructed by users.")
        end
        tembed:embed(docs.link)
        if docs.properties then 
            local count, keys = 0, {}; 
            for key in pairs(docs.properties) do 
                insert(keys, key)
            end
            sort(keys, alphabetize)
            tembed:description(concat(keys, ",\n"):codeblock())
        else 
            tembed:description('%s does not have any uninherited properties.' % name)
        end
        insert(embeds, #tembed)
    end 
end

local function add_method_to_embed(embed, class, name, method)
    embed:field{
        name = display_arguments("%s:%s" % {class, name}, method.arguments, method.method_arguments, false); 
        value = "Returns: %s\n" % resolve_references(method.returns)
        .. resolve_references(method.method_description)
    }
end

local function generate_methods(name)
    local docs = plugin.docs[name]
    if docs then 
        local embeds = {}
        plugin.embeds.methods[name] = embeds
        local tembed = Embed()
        if docs.class then 
            tembed:title("Methods of %s" % display_arguments(docs.class, docs.constructor, nil, false))
        else 
            tembed:title("Methods of %s()" % name)
            tembed:textfooter("Instances of this class should not be constructed by users.")
        end
        tembed:url(docs.link)
        insert(embeds, #tembed)
        if docs.methods then 
            local count, keys = 0, {}; 
            for key in pairs(docs.methods) do 
                insert(keys, key)
            end
            sort(keys, alphabetize)
            tembed:description(concat(keys, ",\n"):codeblock())
        else 
            tembed:description('%s does not have any uninherited methods.' % name)
        end
    end 
end


local lua_word = ("_" + lpeg.alpha) * ("_" + lpeg.alnum)^0
local proper_noun = lpeg.upper * (lpeg.alnum)^0

local property_patt= lpeg.C(proper_noun) * "." * lpeg.C(lua_word)
local method_patt = lpeg.C(proper_noun) * lpeg.S":." * lpeg.C(lua_word)

local function command_overview(cmd, msg, content)
    local class = grep_class(content:trim())
    if class then 
        if not plugin.embeds.overview[class] then 
            generate_overview(class)
        end
        util.fold(plugin.embeds.overview[class], embedandreply, msg)
    end
end

local function command_property(cmd, msg, content)
    local class , prop = property_patt:match(content:trim())
    if class then 
        class = grep_class(class)
        local docs = plugin.docs[class]
        prop = grep(prop, docs.properties)
        local property = docs.properties[prop]
        local out = Embed()
        out:title(
            "%s.%s" % {class, prop}
        )
        if docs.superclass then 
            out:url(docs.link .. '#properties-inherited-from-' ..docs.superclass:lower())
        else
            out:url(docs.link .. '#properties')
        end
        out:description("Type : %s\n" % resolve_references( property.type )
        ..resolve_references(property.desc))
        if prop.superclass then 
            embed:field{ name = "Inherited from"; value = superclassToTitle(prop.superclass)}
        end
        return {embed = #out}
    end
end

local to_remove = lpeg.S[[(),]]/""
local to_hyphen = lpeg.S[[ ]]/"-"

local replacers = {
    ['('] = "",
    [')'] = "",
    [','] = "",
    [' '] = "-"
}

local url_selector = lpeg.Cs(syntax.anywhere(to_remove + to_hyphen))

local function url_selector(str)
    return '#' .. lpeg.gsub(str:lower(), lpeg.S[[(),]] + lpeg.space^1, replacers)
end

local function command_method(cmd, msg, content)
    local class , meth = method_patt:match(content:trim())
    if class then 
        class = grep_class(class)
        local docs = plugin.docs[class]
        meth = grep(meth, docs.methods)
        local method = docs.methods[meth]
        local urls= url_selector(display_arguments(meth, method.arguments, nil, false))
        local out = Embed()
        out:title(
            display_arguments("%s%s%s" % {class, method.static and "." or ":", meth}, method.arguments, method.method_arguments, false)   
        )
        out:url(docs.link .. urls)
        out:description("Returns: %s\n" % resolve_references(method.returns)
        .. resolve_references(method.method_description))
        if method.superclass then 
            out:field{ name = "Inherited from"; value = superclassToTitle(method.superclass)}
        end
        if method.static then 
            out:textfooter("This is a static method")
        end
        return {embed = #out}
    end
end
local is_single = syntax.anywhere(lpeg.S":.")
local function command_properties(cmd, msg, content)
    if is_single:match(content) then 
        return command_property(cmd, msg, content)
    else
        local class = grep_class(content:trim())
        if class then 
            if not plugin.embeds.properties[class] then 
                generate_properties(class)
            end
            util.fold(plugin.embeds.properties[class], embedandreply, msg)
        end
    end
end
local function command_methods(cmd, msg, content)
    if is_single:match(content) then 
        return command_method(cmd, msg, content)
    else
        local class = grep_class(content:trim())
        if class then 
            if not plugin.embeds.methods[class] then 
                generate_methods(class)
            end
            util.fold(plugin.embeds.methods[class], embedandreply, msg)
        end
    end
end

local function command_docs(cmd, msg, content, ...) 
    content = content:trim()
    if content == 'methods' then
        return call_command_args(msg, "->docs.methods", ...)
    elseif content == 'properties' then 
        return call_command_args(msg, "->docs.properties", ...)
    elseif is_single:match(content) then 
        return command_property(cmd, msg, content) or command_method(cmd, msg, content)
    else
        return command_overview(cmd, msg, content)
    end
end

local function register_doc_commands()
    PublicCommand{
        name = "docs",
        body = command_docs,
        usage = "{Class|Class.property|Class.staticMethod|Class.method}|methods|properties",
        requiredPermissions = {'sendMessages'},
        conds = {
            predicates = {
                [5] = hasContent
            }
        },
        desc = "Gets the documentation overview for a discordia class."
    }
    
    PublicCommand{
        name = "docs.properties",
        body = command_properties,
        usage = "{query}",
        conds = {
            predicates = {
                [5] = hasContent
            }
        },
        requiredPermissions = {'sendMessages'},
        desc = "Gets the complete property list for a class or the information for a specfic property."
    }   
    PublicCommand{
        name = "docs.methods",
        body = command_methods,
        usage = "{query}",
        conds = {
            predicates = {
                [5] = hasContent
            }
        },
        requiredPermissions = {'sendMessages'},
        desc = "Gets user info."
    }  
end

local function set_indexed_classes() plugin.indexed_classes = true end

if not plugin.indexed_classes then
    coroutine.wrap(tasks)(
        index_classes,
        register_doc_commands,
        set_indexed_classes
    )
else register_doc_commands()
end



--invite : https://discordapp.com/api/oauth2/authorize?client_id=269653692729262090&scope=bot&permissions=0

-- declare commands --

PublicCommand{
    name = "math",
    body = command_math,
    usage = "{query}",
    parser = arithmetic,
    requiredPermissions = {'sendMessages'},
    desc = "Returns the result of an arithmetic expression."
}

PublicCommand{
    name = "userinfo",
    body = command_whois,
    parser = whois_parser,
    usage = "[@user|user-id|query]",
    requiredPermissions = {'sendMessages'},
    desc = "Gets user info."
}

PublicCommand{
    name = "ginfo",
    body = command_ginfo,
    parser = syntax.everything,
    usage = "",
    requiredPermissions = {'sendMessages'},
    desc = "Gets guild info."
}

PublicCommand{
    name = "avatar",
    body = command_avatar,
    parser = whois_parser,
    usage = "[@user|user-id|query]",
    requiredPermissions = {'sendMessages'},
    desc = "Gets user avatar."
}

PublicCommand{
    name = "source",
    body = command_source,
    usage = "{command}",
    requiredPermissions = {'sendMessages'},
    desc = "Gets the definition of a command."
}

PublicCommand{
    name = "fw",
    body = command_fullwidth,
    usage = "{text}",
    parser = syntax.everything,
    requiredPermissions = {'sendMessages'},
    desc = "Makes text full-width."
}

PublicCommand{
    name = "emoji",
    body = command_emoji,
    usage = "{text}",
    parser = syntax.everything,
    requiredPermissions = {'sendMessages'},
    desc = "Makes text into emojis."
}

PublicCommand{
    name = ">",
    body = command_blockShift,
    usage = "{bloc-numeral} {text}",
    parser = shift_parser,
    requiredPermissions = {'sendMessages'},
    desc = "Shifts basic latin text to the given unicode block."
}

local steal = PublicCommand{
    name = "steal",
    body = command_steal,
    usage = "",
    parser = syntax.everything,
    requiredPermissions = {'sendMessages', 'readMessageHistory', 'useExternalEmojis'},
    desc = ""
}

-- cond override for protected commands --

steal.conds = {
    predicates = {
        hasRequiredpermissions,
        inWhitelistedChannel,
        owner
    }
}

Group:sethelp(
    PublicCommand{
        name = "help",
        body = T.Command.command_help,
        usage = "[query]",
        requiredPermissions = {'sendMessages'},
        desc = "Gets command information."
    }
)

-- administration commands --

local AdminGroup = T.Command.Group{
    name = "public/admin"
}

local AdminCommand = T.Command:extend{
    prefix = "",
    plugin = plugin,
    src = plugin:src(),
    scope = "admin",
    __pipes = false,
    conds = {
        predicates = {
            util.guild_only,
            hasRequiredpermissions,
            owner
        }
    },
    group = AdminGroup
}

local function command_getwhitelist(cmd, msg)
    return get_whitelist_document(cmd.plugin, msg.channel.id) and 
    "<#%s> is whitelisted" % msg.channel.id
    or 
    "<#%s> is __not__ whitelisted." % msg.channel.id
end

local function command_addwhitelist(cmd, msg)
    local document = whitelist_document(msg.channel.id, true)
    add_document(document, 'whitelist')
    plugin.whitelist[msg.channel.id] = document
    return "<#%s> whitelisted!" % msg.channel.id
end

local function command_popwhitelist(cmd, msg)
    pop_document(msg.channel.id, 'whitelist')
    plugin.whitelist[msg.channel.id] = nil
    return "<#%s> unwhitelisted" % msg.channel.id
end

local function cleanContent(text)
    return text --verbose but I cba being elegant 
        :gsub('<@(%d+)>', "<@\xE2\x80\x8B%1>")
        :gsub('<@!(%d+)>', "<@!\xE2\x80\x8B%1>")
        :gsub('<@&(%d+)>', "<@&\xE2\x80\x8B%1>")
        :gsub('<#(%d+)>', "<#\xE2\x80\x8B%1>")
        :gsub('<a?(:.+:)%d+>', '%1')
        :gsub('@everyone', "@\xE2\x80\x8Beveryone")
        :gsub('@here', "@\xE2\x80\x8Bhere")
end

local function command_getblacklist(cmd, msg, content)
    local user;
    if content == nil then 
        user = msg.mentionedUsers.first
    else 
        user = msg.client:getUser(content:trim())
    end 

    if user then 
        local document = get_userblacklist_document(plugin, user.id)
        return document and ("%s is blacklisted." % cleanContent(user.tag:sanitize())) or ("%s is __not__ blacklisted." % cleanContent(user.tag:sanitize()))
    end
end

local function command_addblacklist(cmd, msg, content)
    local user;
    if content == nil then 
        user = msg.mentionedUsers.first
    else 
        user = msg.client:getUser(content:trim())
    end 

    if user and not get_userblacklist_document(plugin, user.id) then 
        msg.client.owner:send("%s `(%s, %s)` was blacklisted." % {user.mentionString, user.tag, user.id})
        local document = userblacklist_document(user.id)
        add_document(document, 'userblacklist')
        plugin.whitelist[user.id] = document
        return "%s was blacklisted." % cleanContent(user.tag:sanitize())
    end
end

local function command_remblacklist(cmd, msg, content)
    local user;
    if content == nil then 
        user = msg.mentionedUsers.first
    else 
        user = msg.client:getUser(content:trim())
    end 

    if user and get_userblacklist_document(cmd.plugin,user.id) then 
        msg.client.owner:send("%s `(%s, %s)` was unblacklisted." % {user.mentionString, user.tag, user.id})
        pop_document(user.id, 'userblacklist')
        return "%s was unblacklisted." % cleanContent(user.tag:sanitize())
    end
end

local function command_reload(cmd, msg, content)
    local result, res = plugin:reload()
    if result == true then
        return "%s reloaded successfully!" % plugin:name()
    elseif result == false then
        msg.client.owner:send('%s failed to load:\n%s' % {plugin:name(), res or '<no error provided>'})
        return "%s failed to load successfully!" % plugin:name()
    end
end

local function command_permissify(cmd, msg, content)
    if content then
        call_command(msg, content)
    end
end

local function command_src_any(_, msg, content)
    if content then 
        local cinfo = T.Command.find(content:trim())
        local cmd = T.Command.resolveName(cinfo.command)
        if cmd then
            local info = debug.getinfo(cmd.body)
            if info.what == 'Lua' then
                fs.readFile(info.source:sub(2), T.here())
                local err, content = coroutine.yield()
                if not err then 
                    local lines = content:split('\n')
                    local func = {}
                    for i = info.linedefined, info.lastlinedefined do 
                        table.insert(func, lines[i])
                    end
                    local data = table.concat(func, '\n')
                    if info.nups > 0 then 
                        msg:reply("This function depends on upvalues in it's enclosing scope.")
                    end
                    if #lines < 20 then 
                        return data:lang('lua')
                    else
                        return {file = {cmd.name .. ".lua", data}}
                    end
                else
                    return "Error locating function!"
                end
            end
        end
    end
end

local admin_patt = lpeg.R()

for _, cmd in AdminGroup:commands() do 
    admin_patt = admin_patt + lpeg.P(cmd.nonce)
end

local regular_patt = lpeg.P(PublicCommand.prefix)

local cleaner = regular_patt + admin_patt

local function predicate (i) 
    return i.author.id == "<bot's id here>" or cleaner:match(i.content) 
end

local function command_nuke(_,msg)
    msg:delete()
    local msgs = msg.channel:getMessages()
    local toclean = msgs:toArray(_,predicate)
    local count = #toclean
    if count > 1 then msg.channel:bulkDelete(toclean) 
    elseif count > 0 then toclean:iter()():delete()
    end
end

AdminCommand{
    name = "@+",
    body = command_addblacklist,
    desc = "Adds a user to the global bot blacklist.",
    requiredPermissions = {'sendMessages'},
    usage = "{@user|user-id}",
}

AdminCommand{
    name = "@-",
    body = command_remblacklist,
    desc = "Removes a user from the global bot blacklist.",
    requiredPermissions = {'sendMessages'},
    usage = "{@user|user-id}",
}

AdminCommand{
    name = "@?",
    body = command_getblacklist,
    desc = "Checks for a blacklist entry.",
    requiredPermissions = {'sendMessages'},
    usage = "{@user|user-id}"
}

AdminCommand{
    name = "??",
    body = command_getwhitelist,
    desc = "Checks for a whitelist entry.",
    requiredPermissions = {'sendMessages'},
    usage = ""
}


AdminCommand{
    name = "++",
    body = command_addwhitelist,
    desc = "Adds a channel to the bot whitelist.",
    requiredPermissions = {'sendMessages'},
    usage = "",
}

AdminCommand{
    name = "--",
    body = command_popwhitelist,
    desc = "Removes a channel from the bot whitelist.",
    requiredPermissions = {'sendMessages'},
    usage = "",
}

AdminCommand{
    name = "=<",
    body = command_reload,
    desc = "Reloads %s." % plugin:name(),
    requiredPermissions = {'sendMessages'},
    usage = "",
}

AdminCommand{
    name = "&",
    body = command_permissify,
    parser = syntax.everything,
    desc = "Overrides the usage permissions of a regular command.",
    requiredPermissions = {'sendMessages'},
    usage = ""
}

AdminCommand{
    name = "are_idiots_making_their_token_public?",
    body = command_tokenfind,
    parser = syntax.everything,
    usage = "",
    requiredPermissions = {'sendMessages', 'attachFiles'},
    desc = "Please dont make your token public c:"
}

AdminCommand{
    name = "$",
    body = command_eval,
    usage = "",
    parser = syntax.codeblock,
    requiredPermissions = {'sendMessages'},
    desc = ""
}

AdminCommand{
    name = "=",
    body = command_src_any,
    usage = "",
    requiredPermissions = {'sendMessages'},
    desc = ""
}

AdminCommand{
    name = "/",
    body = command_nuke,
    usage = "",
    requiredPermissions = {'readMessageHistory','manageMessages'}
}
